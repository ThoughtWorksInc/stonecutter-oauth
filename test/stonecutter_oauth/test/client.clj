(ns stonecutter-oauth.test.client
  (:require [midje.sweet :refer :all]
            [clj-http.client :as http]
            [stonecutter-oauth.client :as c]))

(facts "about configure"
       (fact "returns a config map when all fields are passed"
             (c/configure ...auth-provider-url...
                          ...client-id...
                          ...client-secret...
                          ...callback-uri...)
             => {:auth-provider-url ...auth-provider-url...
                 :client-id ...client-id...
                 :client-secret ...client-secret...
                 :callback-uri ...callback-uri...})

       (tabular
         (fact "returns invalid configuration when any fields are missing"
               (c/configure ?auth-provider-url ?client-id ?client-secret ?callback-uri)
               => :invalid-configuration)
         ?auth-provider-url ?client-id ?client-secret ?callback-uri
         nil                :not-nil   :not-nil       :not-nil
         :not-nil           nil        :not-nil       :not-nil
         :not-nil           :not-nil   nil            :not-nil
         :not-nil           :not-nil   :not-nil       nil)
       
       (fact "accepts optional additional configuration arguments for openid connect"
             (c/configure ...auth-provider-url...
                          ...client-id...
                          ...client-secret...
                          ...callback-uri...
                          :protocol :openid)
             => {:auth-provider-url ...auth-provider-url...
                 :client-id ...client-id...
                 :client-secret ...client-secret...
                 :callback-uri ...callback-uri...
                 :protocol :openid})
       
       (facts "about validating additional configuration arguments"
              (fact "returns invalid configuration when protocol is not recognised"
                    (c/configure ...auth-provider-url...
                                 ...client-id...
                                 ...client-secret...
                                 ...callback-uri...
                                 :protocol :invalid) => :invalid-configuration)))

(def test-config (c/configure "<auth-provider-url>" "<client-id>" "<client-secret>" "<callback-uri>"))

(facts "about default protocol"
       (facts "about authorisation-redirect-response"
              (fact "returns a redirect response to the correct endpoint"
                    (:status (c/authorisation-redirect-response test-config)) => 302
                    (get-in (c/authorisation-redirect-response test-config) [:headers "Location"])
                    => "<auth-provider-url>/authorisation?client_id=<client-id>&response_type=code&redirect_uri=<callback-uri>")) 


       (facts "about request-access-token!"
              (fact "obtains an access token from the auth server"
                    (c/request-access-token! test-config ...auth-code...)
                    => {:user-info {:sub "<user-id>"}
                        :access_token "<access-token>"
                        :token_type "bearer"}
                    (provided
                      (http/post "<auth-provider-url>/api/token"
                                 {:form-params {:grant_type "authorization_code"
                                                :redirect_uri "<callback-uri>"
                                                :code ...auth-code...
                                                :client_id "<client-id>"
                                                :client_secret "<client-secret>"}})
                      => {:body "{\"user-info\":{\"sub\":\"<user-id>\"},\"access_token\":\"<access-token>\",\"token_type\":\"bearer\"}"}))

              (tabular
                (fact "throws an exception when the access token response body is not of the expected form"
                      (against-background
                        (http/post "<auth-provider-url>/api/token" anything) => {:body ?body})
                      (c/request-access-token! test-config ...auth-code...) => (throws Exception))

                ?body
                "{\"access_token\":\"<access-token>\",\"token_type\":\"bearer\"}"
                "{\"user-info\":{},\"access_token\":\"<access-token>\",\"token_type\":\"bearer\"}"
                "{\"user-info\":{\"sub\":\"<user-id>\"},\"token_type\":\"bearer\"}"
                "{\"user-info\":{\"sub\":\"<user-id>\"},\"access_token\":\"<access-token>\"}"
                "{\"user-info\":{\"sub\":\"<user-id>\"},\"access_token\":\"<access-token>\",\"token_type\":\"not-bearer\"}")))

(def openid-test-config (c/configure "ISSUER" "CLIENT_ID" "<client-secret>" "<callback-uri>"
                                     :protocol :openid))

(facts "about openid connect protocol"
       (facts "about authorisation-redirect-response"
              (fact "returns a redirect response to the correct endpoint"
                    (:status (c/authorisation-redirect-response openid-test-config)) => 302
                    (get-in (c/authorisation-redirect-response openid-test-config) [:headers "Location"])
                    => "ISSUER/authorisation?client_id=CLIENT_ID&response_type=code&redirect_uri=<callback-uri>&scope=openid"))

       (facts "about request-access-token!"
              (fact "obtains an access token and id token from the auth server"
                    (c/request-access-token! openid-test-config ...auth-code...)
                    => {:id_token "ID_TOKEN"
                        :access_token "<access-token>"
                        :token_type "bearer"}
                    (provided
                      (http/post "ISSUER/api/token"
                                 {:form-params {:grant_type "authorization_code"
                                                :redirect_uri "<callback-uri>"
                                                :code ...auth-code...
                                                :client_id "CLIENT_ID"
                                                :client_secret "<client-secret>"}})
                      => {:body "{\"id_token\":\"ID_TOKEN\",\"access_token\":\"<access-token>\",\"token_type\":\"bearer\"}"}))))


