(ns stonecutter-oauth.jwt
  (:require [clojure.walk :as walk]
            [cheshire.core :as json]
            [clj-http.client :as http])
  (:import [org.jose4j.jwk JsonWebKey$Factory]
           [org.jose4j.jwt.consumer JwtConsumerBuilder]))

(defn get-public-key-string-from-jwk-set-url [jwks-url]
  (let [keys (-> (http/get jwks-url {:accept :json :as :json})
                 :body
                 :keys)]
    (when-not (= 1 (count keys))
      (throw ex-info "stonecutter-oauth only supports one key"
             {:jwk-set-keys keys :jwks-url jwks-url}))
    (json/generate-string (first keys))))

(defn json->key-pair [json-string] (JsonWebKey$Factory/newJwk json-string))

(defn decode [config-m id-token rsa-public-key-string]
  (let [rsa-public-key (json->key-pair rsa-public-key-string)
        audience (:client-id config-m)
        issuer (:auth-provider-url config-m)
        jwtConsumer (-> (JwtConsumerBuilder.)
                        (.setRequireExpirationTime)
                        (.setAllowedClockSkewInSeconds 30)
                        (.setRequireSubject)
                        (.setExpectedIssuer issuer)
                        (.setExpectedAudience (into-array [audience]))
                        (.setVerificationKey (.getKey rsa-public-key))
                        (.build))]
    (->> (.processToClaims jwtConsumer id-token)
         .getClaimsMap
         (into {})
         walk/keywordize-keys)))
