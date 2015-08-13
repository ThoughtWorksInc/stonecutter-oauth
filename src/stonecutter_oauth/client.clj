(ns stonecutter-oauth.client
  (:require [ring.util.response :as r]
            [cheshire.core :as json]
            [clj-http.client :as http]))

(defn authorisation-redirect-response [stonecutter-config]
  (let [callback-uri (:callback-uri stonecutter-config)
        oauth-authorisation-path (str (:auth-provider-url stonecutter-config)
                                      "/authorisation?client_id=" (:client-id stonecutter-config)
                                      "&response_type=code&redirect_uri=" callback-uri)]
    (r/redirect oauth-authorisation-path)))

(defn all-present? [m required-keys]
  (every? (partial get m) required-keys))

(defn valid-user-info? [user-info-m]
  (all-present? user-info-m [:sub]))

(defn valid-token-body? [token-body]
  (and (all-present? token-body [:user-info :access_token :token_type])
       (valid-user-info? (:user-info token-body))
       (= "bearer" (:token_type token-body))))

(defn request-access-token! [stonecutter-config auth-code]
  (let [callback-uri (:callback-uri stonecutter-config)
        oauth-token-path (str (:auth-provider-url stonecutter-config) "/api/token")
        token-response (http/post oauth-token-path
                                  {:form-params {:grant_type    "authorization_code"
                                                 :redirect_uri  callback-uri
                                                 :code          auth-code
                                                 :client_id     (:client-id stonecutter-config)
                                                 :client_secret (:client-secret stonecutter-config)}})
        token-body (-> token-response :body (json/parse-string keyword))]

    (if (valid-token-body? token-body)
      token-body
      (throw (ex-info "Invalid token response" {:token-response-keys (keys token-body)})))))

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
