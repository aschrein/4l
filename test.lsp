(scope
  (let print-times
    (lambda (i body)
      (if (cmp lt i 1)
        nil
        (scope
          (print body)
          (print-times (sub i 1) (deref body))
        )
      )
    )
  )
  (print-times 10 (quote (format "hello %i" i)))
  (print "####################")
  (for-range i 0 10
    (print (format "hello %i" i))
  )
  (let make_vector-f32
    (lambda (x y z w)
      (print (format "make_vector f32 %f %f %f %f" x y z w))
    )
  )
  (let exec-times
    (lambda (i body)
      (if (cmp lt i 1)
        nil
        (scope
          (body)
          (exec-times (sub i 1) (deref body))
        )
      )
    )
  )
  (make_vector-f32 0.0 1.0 2.0 3.0)
  (add-mode llvm
    (let make_vector-f32
      (lambda (x y z w)
        (make_vector f32 x y z w)
      )
    )
    (let make_vf32-zero
      (lambda ()
        (make_vector f32 0.0 0.0 0.0 0.0)
      )
    )
    (let make_vf32-one
      (lambda ()
        (make_vector f32 1.0 1.0 1.0 1.0)
      )
    )
    (module
      (function i32 main
                     (
                      (i32 argc)
                      ((pointer (pointer i8)) argv)
                     )
        (let a (make_vector-f32 1.0 2.0 3.0 4.0))
        (let b (make_vector f32 0.0 1.0 2.0 3.0))
        (let c (fadd a b))
        (let c (fadd c make_vf32-zero))
        (let c (fadd c make_vf32-one))
        (let *c (alloca (typeof c)))
        (store c *c)
        (let tmp_buf (bitcast (alloca (array i8 256)) (pointer i8)))
        (for-range i 0 10
          (let c (load *c))
          (let c (fadd c c))
          (store c *c)
;;          (puts "fesffe")
;;          (puts (format tmp_buf "666 = %f" 666.0))
;;          (puts tmp_buf)
          (for-range j 0 4
            (puts (format tmp_buf "c[%i] = %f" j (extract_element c j)))
          )
;;          (debug_assert (fcmp eq (extract_element c 0) (2.0)))
        )
        ;; (exec-times 10 (quote (debug_assert (fcmp eq (extract_element c 0) (2.0)))))
        ;; (debug_assert (fcmp eq (extract_element c 1) (4.0)))
        ;; (debug_assert (fcmp eq (extract_element c 2) (6.0)))
        ;; (debug_assert (fcmp eq (extract_element c 3) (8.0)))
        ;; ; Test vector logic ops
        ;; (debug_assert (all (fcmp eq c (make_vector f32 2.0 4.0 6.0 8.0))))
        ;; (debug_assert (any (fcmp eq c (make_vector f32 0.0 4.0 0.0 0.0))))
        ;; (debug_assert (none (fcmp eq c (make_vector f32 2.1 4.1 6.1 8.1))))
        ;; ; Test negation
        ;; (debug_assert (not (all (fcmp eq c (make_vector f32 2.0 4.0 6.0 8.1)))))
        ;; (debug_assert (not (any (fcmp eq c (make_vector f32 0.0 0.0 0.0 0.0)))))
        ;; (debug_assert (not (none (fcmp eq c (make_vector f32 0.0 0.0 6.0 0.0)))))
        ;; ; Test store/load
        ;; (let tmp_ptr (alloca (vector f32 4)))
        ;; (store c tmp_ptr)
        ;; (debug_assert (all (fcmp eq c (load tmp_ptr))))
        ;; (printf "hello world!")
        ;; (debug_assert (icmp eq 1 1))
        ;; (debug_assert (icmp eq 0 1))
        (ret 0)
      )
    )
  )
)
