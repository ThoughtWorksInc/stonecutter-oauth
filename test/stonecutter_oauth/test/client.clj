(ns stonecutter-oauth.test.client
  (:require [midje.sweet :refer :all]
            [clj-http.client :as http]
            [stonecutter-oauth.client :as c])
  (:import [org.jose4j.jwk JsonWebKey$Factory JsonWebKey$OutputControlLevel RsaJwkGenerator]
           [org.jose4j.jwk RsaJwkGenerator JsonWebKey$OutputControlLevel]
           [org.jose4j.jwt.consumer JwtConsumerBuilder]))

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
                          :protocol :openid
                          :public-key ...public-key...)
             => {:auth-provider-url ...auth-provider-url...
                 :client-id ...client-id...
                 :client-secret ...client-secret...
                 :callback-uri ...callback-uri...
                 :protocol :openid
                 :public-key ...public-key...})
       
       (future-fact "validates that protocol is recognised, and that public key is present when using openid connect protocol"))

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
                                     :protocol :openid
                                     :public-key "TODO: Needs to be an actual public key"))


(defn json->key-pair [json-string] (JsonWebKey$Factory/newJwk json-string))

(defn load-key-pair [path]
  (-> (slurp path) json->key-pair))

(defn decode [rsa-key-pair audience issuer id-token]
  (let [jwtConsumer (-> (JwtConsumerBuilder.)
                        (.setRequireExpirationTime)
                        (.setAllowedClockSkewInSeconds 30)
                        (.setRequireSubject)
                        (.setExpectedIssuer issuer)
                        (.setExpectedAudience (into-array [audience]))
                        (.setVerificationKey (.getKey rsa-key-pair))
                        (.build))]
    (.getClaimsMap (.processToClaims jwtConsumer id-token))))

(def token-expiring-in-500-years "eyJraWQiOiJ0ZXN0LWtleSIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJJU1NVRVIiLCJhdWQiOiJDTElFTlRfSUQiLCJleHAiOjE3MjA3OTkzMjUyLCJpYXQiOjE0Mzk5OTI3NDAsInN1YiI6IlNVQkpFQ1QiLCJyb2xlIjoiYWRtaW4iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZW1haWwiOiJlbWFpbEBhZGRyZXNzLmNvbSJ9.PQWWJQGECzC8EchkfwGjQBBUfhFGoLDOjZ1Ohl1t-eo8rXDO4FxONk3rYEY9v01fVg3pzQW8zLJYcZ73gyE2ju8feHhwS8wYwcsgKq6XC-Zr9LwRJIeFpZoVcgMpvW21UHX1bxAhHE7WM_UzSerKtGkIuK21XraGVTiIB-0o8eWOJX0Rud8FXC3Cr0LdZeqDytPZDwM1Pbcr0eFyfNq9ngi75BFNTGHCMLGshJGt1LvQhDtTWifXDlwW5uk-kuOVavnQGK_i7qvrcy8c7lFCCPqd5X3x6EZJyfk-BZGgDT1ySwdM2EjRAi1W1nPAmdWms9rts0rkbk_Q73gEkWQpOw")

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

(future-facts "about decoding openid connect id tokens"
       (fact "can decode a signed id token"
             (let [keypair (load-key-pair "./test/stonecutter_oauth/test-key.json")]
               (decode keypair "CLIENT_ID" "ISSUER" token-expiring-in-500-years) => empty?)))
