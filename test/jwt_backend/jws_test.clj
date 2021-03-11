(ns jwt-backend.jws-test
  (:use clojure.test
        jwt-backend.jws))

(deftest test-match-token
  (testing "match-token"
    (is (nil? (match-token nil nil)))
    (is (= "Test" (match-token "Bearer" "Bearer Test")))))

(deftest test-match-tokens
  (testing "match-tokens"
    (is (nil? (match-tokens nil nil nil)))
    (is (nil? (match-tokens nil ["Bearer"] "Token Test2")))
    (is (= "Test2" (match-tokens nil ["Token"] "Token Test2")))
    (is (= "Test" (match-tokens nil ["Bearer"] "Bearer Test")))
    (is (= "Test" (match-tokens nil ["Bearer" "Token"] "Bearer Test")))
    (is (= "Test" (match-tokens nil ["Bearer" "Token"] "Token Test")))
    (is (= "Test" (match-tokens nil ["Bearer" "Token"] "Bearer Test")))))