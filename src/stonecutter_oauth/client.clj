(ns stonecutter-oauth.client
  (:require [ring.util.response :as r]
            [cheshire.core :as json]
            [clj-http.client :as http]))

(defn authorisation-redirect-response [stonecutter-config]
  (let [callback-uri (:callback-uri stonecutter-config)
        oauth-authorisation-path (str (:auth-provider-url stonecutter-config)
                                      "/authorisation?client_id=" (:client-id stonecutter-config)
                                      "&response_type=code&redirect_uri=" callback-uri)]
    (-> (r/redirect oauth-authorisation-path)
        (assoc-in [:headers "accept"] "text/html"))))

(defn request-access-token! [stonecutter-config auth-code]
  (let [callback-uri (:callback-uri stonecutter-config)
        oauth-token-path (str (:auth-provider-url stonecutter-config) "/api/token")
        token-response (http/post oauth-token-path
                                  {:form-params {:grant_type    "authorization_code"
                                                 :redirect_uri  callback-uri
                                                 :code          auth-code
                                                 :client_id     (:client-id stonecutter-config)
                                                 :client_secret (:client-secret stonecutter-config)}})]
    {:status :success
     :token (-> token-response :body (json/parse-string keyword))}))

(defn configure [auth-provider-url
                 client-id
                 client-secret
                 callback-uri]
  (if (and auth-provider-url client-id client-secret callback-uri)
    {:auth-provider-url auth-provider-url
     :client-id client-id
     :client-secret client-secret
     :callback-uri callback-uri}
    :invalid-configuration))
