(ns stonecutter-oauth.test.jwt
 (:require [midje.sweet :refer :all]
           [clj-http.client :as http]
           [stonecutter-oauth.client :as c]
           [stonecutter-oauth.jwt :as jwt]))

(def openid-test-config (c/configure "ISSUER" "CLIENT_ID" "<client-secret>" "<callback-uri>"
                                     :protocol :openid))

(def token-expiring-in-500-years "eyJraWQiOiJ0ZXN0LWtleSIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJJU1NVRVIiLCJhdWQiOiJDTElFTlRfSUQiLCJleHAiOjE3MjA3OTkzMjUyLCJpYXQiOjE0Mzk5OTI3NDAsInN1YiI6IlNVQkpFQ1QiLCJyb2xlIjoiYWRtaW4iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZW1haWwiOiJlbWFpbEBhZGRyZXNzLmNvbSJ9.PQWWJQGECzC8EchkfwGjQBBUfhFGoLDOjZ1Ohl1t-eo8rXDO4FxONk3rYEY9v01fVg3pzQW8zLJYcZ73gyE2ju8feHhwS8wYwcsgKq6XC-Zr9LwRJIeFpZoVcgMpvW21UHX1bxAhHE7WM_UzSerKtGkIuK21XraGVTiIB-0o8eWOJX0Rud8FXC3Cr0LdZeqDytPZDwM1Pbcr0eFyfNq9ngi75BFNTGHCMLGshJGt1LvQhDtTWifXDlwW5uk-kuOVavnQGK_i7qvrcy8c7lFCCPqd5X3x6EZJyfk-BZGgDT1ySwdM2EjRAi1W1nPAmdWms9rts0rkbk_Q73gEkWQpOw")

(def token-content {:aud "CLIENT_ID"
                    :email "email@address.com"
                    :email_verified true
                    :exp 17207993252
                    :iat 1439992740
                    :iss "ISSUER"
                    :role "admin"
                    :sub "SUBJECT"})

(facts "about decoding openid connect id tokens"
       (fact "can decode a signed id token using provided id token"
             (let [public-key-string (slurp "./test/stonecutter_oauth/test-key.json")]
               (jwt/decode openid-test-config token-expiring-in-500-years public-key-string) => token-content)))

(facts "about getting public keys from jwk-set-url"
       (fact "returns the only key in the 'set'"
             (jwt/get-public-key-string-from-jwk-set-url ...jwks-url...) => "{\"some-key\":1}"
              (provided
                (http/get ...jwks-url... {:accept :json :as :json})
                => {:body {:keys [{:some-key 1}]}}))

       (fact "throws an exception when the 'set' contains more than one key"
             (jwt/get-public-key-string-from-jwk-set-url ...jwks-url...) => (throws Exception)
             (provided
               (http/get ...jwks-url... {:accept :json :as :json})
               => {:body {:keys [{:some-key 1} {:some-other-key 2}]}})))
