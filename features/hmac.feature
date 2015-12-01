Feature: Message signing functionality

  Scenario Outline: Sign different requests with no body
    Given a new request
      And the endpoint "<method>" "http://<domain><request_uri>"
      And the header "X-Authorization-Timestamp" "<timestamp>"
      And the header "Date" "<timestamp>"
      And the header "Host" "<domain>"
      And a <version> signer with the "<digest>" digest
      And the fixed server time "<server_time>"
      And the auth header "id" "efdde334-fe7b-11e4-a322-1697f925ec7b"
      And the auth header "nonce" "d1954337-5319-4821-8427-115542e08d10"
      And the auth header "realm" "Pipet%20service"
    When I sign the request with the secret key "<secret>"
    Then I should see the signature "<signature>"

    Examples: Test cases
    | method | domain                  | request_uri                    | timestamp  | server_time | version | digest | secret                                       | signature                                    |
    | GET    | example.com             | /resource/1?key=value          |            | 1432075982  | v1      | SHA1   | secret-key                                   | 7Tq3+JP3lAu4FoJz81XEx5+qfOc=                 |
    | GET    | example.acquiapipet.net | /v1.0/task-status/133?limit=10 | 1432075982 | 1432075982  | v2      | SHA256 | W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI= | MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc= |

  Scenario Outline: Sign different requests with a body
    Given a new request
      And the endpoint "<method>" "http://<domain><request_uri>"
      And the header "X-Authorization-Timestamp" "<timestamp>"
      And the header "Date" "<timestamp>"
      And the header "Host" "<domain>"
      And the header "Content-Type" "<content_type>"
      And the headers "<add_headers>" in query format
      And the body "<body>"
      And the calculated SHA-256 hash of the body as the header "X-Authorization-Content-SHA256"
      And a <version> signer with the "<digest>" digest
      And the fixed server time "<server_time>"
      And the auth header "id" "efdde334-fe7b-11e4-a322-1697f925ec7b"
      And the auth header "nonce" "d1954337-5319-4821-8427-115542e08d10"
      And the auth header "realm" "Pipet%20service"
      And the auth header "headers" "<add_auth>"
    When I sign the request with the secret key "<secret>"
    Then I should see the signature "<signature>"

    Examples: Test cases
    | method | domain                  | request_uri           | body                                       | add_headers    | add_auth | content_type     | timestamp                     | server_time | version | digest | secret                                       | signature                                    |
    | POST   | example.com             | /resource/1?key=value | test content                               |                |          | text/plain       | Fri, 19 Mar 1982 00:00:04 GMT | 1432075982  | v1      | SHA1   | secret-key                                   | 6DQcBYwaKdhRm/eNBKIN2jM8HF8=                 |
    | POST   | example.com             | /resource/1?key=value | test content                               | Custom1=Value1 | Custom1  | text/plain       | Fri, 19 Mar 1982 00:00:04 GMT | 1432075982  | v1      | SHA1   | secret-key                                   | QRMtvnGmlP1YbaTwpWyB/6A8dRU=                 |
    | POST   | example.acquiapipet.net | /v1.0/task            | {"method":"hi.bob","params":["5","4","8"]} |                |          | application/json | 1432075982                    | 1432075982  | v2      | SHA256 | W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI= | XDBaXgWFCY3aAgQvXyGXMbw9Vds2WPKJe2yP+1eXQgM= |

  Scenario Outline: Sign responses
    Given a new request
      And the endpoint "<method>" "http://<domain><request_uri>"
      And the header "X-Authorization-Timestamp" "<timestamp>"
      And the header "Date" "<timestamp>"
      And the header "Host" "<domain>"
      And a <version> signer with the "<digest>" digest
      And the fixed server time "<server_time>"
      And the auth header "id" "efdde334-fe7b-11e4-a322-1697f925ec7b"
      And the auth header "nonce" "d1954337-5319-4821-8427-115542e08d10"
      And the auth header "realm" "Pipet%20service"
      And the response body "<response_body>"
    When I sign the response with the secret key "<secret>"
    Then I should see the signature "<signature>"

    Examples: Test cases
    | method | domain                  | request_uri                    | response_body                 | timestamp  | server_time | version | digest | secret                                       | signature                                    |
    | GET    | example.acquiapipet.net | /v1.0/task-status/133?limit=10 | {"id": 133, "status": "done"} | 1432075982 | 1432075982  | v2      | SHA256 | W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI= | M4wYp1MKvDpQtVOnN7LVt9L8or4pKyVLhfUFVJxHemU= |

  Scenario Outline: Identify signatures
    Given a compatibility layer spanning from version 1 to 2 with the "<digest>" digest
     When I try to identify the "<header>" header
     Then I should get <result>

    Examples: Test cases
    | digest | header                                                                                                                                                                                                                                                                                                             | result                        |
    | SHA1   | Acquia efdde334-fe7b-11e4-a322-1697f925ec7b:6DQcBYwaKdhRm/eNBKIN2jM8HF8=                                                                                                                                                                                                                                           | an instance of the v1 signer  |
    | SHA256 | acquia-http-hmac realm="Pipet%20service",id="efdde334-fe7b-11e4-a322-1697f925ec7b",nonce="d1954337-5319-4821-8427-115542e08d10",version="2.0",headers="",signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="                                                                                                  | an instance of the v2 signer  |
    | SHA256 | OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog",oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1318622958",oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",oauth_version="1.0" | no hits for a matching signer |



