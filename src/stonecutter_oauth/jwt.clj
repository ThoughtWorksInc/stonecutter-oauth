(ns stonecutter-oauth.jwt
  (:require [clojure.walk :as walk])
  (:import [org.jose4j.jwk JsonWebKey$Factory JsonWebKey$OutputControlLevel RsaJwkGenerator]
           [org.jose4j.jwk RsaJwkGenerator JsonWebKey$OutputControlLevel]
           [org.jose4j.jwt.consumer JwtConsumerBuilder]))

(defn json->key-pair [json-string] (JsonWebKey$Factory/newJwk json-string))

(defn load-json-web-key [path]
  (-> (slurp path) json->key-pair))

(defn decode [config-m id-token]
  (let [rsa-public-key (:public-key config-m)
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
