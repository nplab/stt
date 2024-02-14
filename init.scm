;;; 
;;; Copyright (C) 2009 M. Tuexen, tuexen@fh-muenster.de
;;;
;;; All rights reserved.
;;; 
;;; Redistribution and use in source and binary forms, with or
;;; without modification, are permitted provided that the
;;; following conditions are met:
;;; 1. Redistributions of source code must retain the above
;;;    copyright notice, this list of conditions and the
;;;    following disclaimer.
;;; 2. Redistributions in binary form must reproduce the
;;;    above copyright notice, this list of conditions and
;;;    the following disclaimer in the documentation and/or
;;;    other materials provided with the distribution.
;;; 3. Neither the name of the project nor the names of
;;;    its contributors may be used to endorse or promote
;;;    products derived from this software without specific
;;;    prior written permission.
;;;  
;;; THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS
;;; ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
;;; BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
;;; MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;;; DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS
;;; BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
;;; EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
;;; LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
;;; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;;; HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
;;; IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
;;; USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
;;; OF SUCH DAMAGE.

(define 2**16 (expt 2 16))
(define 2**32 (expt 2 32))

(define (+mod16 x y)
  (modulo (+ x y) 2**16))
(define (-mod16 x y)
  (modulo (+ x y) 2**16))
(define (*mod16 x y)
  (modulo (* x y) 2**16))
(define (1+mod16 x)
  (+mod16 x 1))
(define (1-mod16 x)
  (-mod16 x 1))

(define (+mod32 x y)
  (modulo (+ x y) 2**32))
(define (-mod32 x y)
  (modulo (- x y) 2**32))
(define (*mod32 x y)
  (modulo (* x y) 2**32))
(define (1+mod32 x)
  (+mod32 x 1))
(define (1-mod32 x)
  (-mod32 x 1))

(define (data-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x00)))
(define (init-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x01)))
(define (init-ack-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x02)))
(define (sack-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x03)))
(define (heartbeat-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x04)))
(define (heartbeat-ack-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x05)))
(define (abort-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x06)))
(define (shutdown-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x07)))
(define (shutdown-ack-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x08)))
(define (error-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x09)))
(define (cookie-echo-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x0a)))
(define (cookie-ack-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x0b)))
(define (ecne-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x0c)))
(define (cwr-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x0d)))
(define (shutdown-complete-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x0e)))
(define (pktdrop-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x81)))
(define (forward-tsn-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #xc0)))
(define (nr-sack-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x10)))
(define (asconf-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #xc1)))
(define (asconf-ack-chunk? x)
  (and (chunk? x) (= (get-chunk-type x) #x80)))

(define (heartbeat-parameter? x)
  (and (parameter? x) (= (get-parameter-type x) #x0001)))
(define (ipv4-address-parameter? x)
  (and (parameter? x) (= (get-parameter-type x) #x0005)))
(define (ipv6-address-parameter? x)
  (and (parameter? x) (= (get-parameter-type x) #x0006)))
(define (cookie-parameter? x)
  (and (parameter? x) (= (get-parameter-type x) #x0007)))
(define (unrecognized-parameter-parameter? x)
  (and (parameter? x) (= (get-parameter-type x) #x0008)))
(define (cookie-preservative-parameter? x)
  (and (parameter? x) (= (get-parameter-type x) #x0009)))
(define (hostname-parameter? x)
  (and (parameter? x) (= (get-parameter-type x) #x000b)))
(define (supported-address-type-parameter? x)
  (and (parameter? x) (= (get-parameter-type x) #x000c)))
(define (ecn-capable-parameter? x)
  (and (parameter? x) (= (get-parameter-type x) #x8000)))
(define (supported-extensions-parameter? x)
  (and (parameter? x) (= (get-parameter-type x) #x8008)))
(define (forward-tsn-supported-parameter? x)
  (and (parameter? x) (= (get-parameter-type x) #xc000)))

(define sctp-remote-udp-encaps-port 0)
(define (sctp-send common-header chunks to-address . rest)
  (apply sctp-send-with-crc32c common-header chunks to-address (cons sctp-remote-udp-encaps-port rest)))
(define (sctp-send-raw common-header bytes to-address . rest)
  (apply sctp-send-raw-with-crc32c common-header bytes to-address (cons sctp-remote-udp-encaps-port rest)))

(define sctp-receive sctp-receive-with-crc32c)

(if (string=? (major-version) "1")
    (use-modules (ice-9 syncase)))

(define-syntax dotimes 
   (syntax-rules () 
     ((_ (var n res) . body) 
      (do ((limit n) 
           (var 0 (+ var 1))) 
          ((>= var limit) res) 
        . body)) 
     ((_ (var n) . body) 
      (do ((limit n) 
           (var 0 (+ var 1))) 
          ((>= var limit)) 
        . body))))

(define-syntax when
  (syntax-rules ()
    ((when condition exp ...)
     (if condition
         (begin
           exp ...)))))

(define-syntax unless
  (syntax-rules ()
    ((when condition exp ...)
     (if (not condition)
         (begin
           exp ...)))))
