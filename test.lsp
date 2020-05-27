(scope
  (let @scope get-scope)
  (let @mode get-mode)
  (let @format
    (lambda (...)
      (set-mode @mode
        (format ...)
      )
    )
  )
  (print (@format "--%i--%f--" 666 (add 777.0 0.1)))
  (let @add
    (lambda (...)
      (add ...)
    )
  )
  (print (@format "--%i--%i--" 1 (@add 1 2)))
  (print (@format "--%i--%i--" 1 (@add 2 2)))
  (let @format-name
    (lambda (l)
      (set-mode @mode
        (format (deref l))
      )
    )
  )
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
    (let print-float4
      (lambda (buf vec)
        (puts (format buf "{%f %f %f %f}"
          (extract_element vec 0)
          (extract_element vec 1)
          (extract_element vec 2)
          (extract_element vec 3)
        ))
      )
    )
    (let print-vector
      (lambda (buf vec)
        (puts "{")
        (for-range i 0 N
          (puts (format buf "%f " (extract_element vec i)))
        )
        (puts "}")
        (putnl)
      )
    )
    (let @sub
      (lambda (...)
        (set-mode @mode
          (sub ...)
        )
      )
    )
    (for-items i ("a" "b" "c" "bye")
      (print i)
    )
    (let @for-items
      (lambda (name items ...)
        (set-mode @mode
          (for-items (unquote name) (items)
            ...
          )
        )
      )
    )
    (module
      (let gen-strcmp
        (lambda (N)
          (function i1 (@format-name (quote "strcmp-%i" N))
                        (
                          ((pointer i8) a)
                          ((pointer i8) b)
                          (i32 size)
                        )
            (let N-1 (@sub N 1))
            (assume (icmp eq (and N (N-1)) 0))
            (assume (icmp eq (and size N-1) 0))
            (assume (icmp eq (and (trunc (ptrtoint a) i32) N-1) 0))
            (assume (icmp eq (and (trunc (ptrtoint b) i32) N-1) 0))
            (let a (bitcast a (pointer (vector i8 N))))
            (let b (bitcast b (pointer (vector i8 N))))
            (let size (udiv size N))
            (let *i (alloca i32))
            (store 0 *i)
            (label loop-header)
            (let i (load *i))
            (let end-loop
              (icmp eq i size)
            )
            (br end-loop ret-true cont1)
            (label cont1)
            (let fail
              (not (all (icmp eq (at a i) (at b i))))
            )
            (br fail ret-false cont2)
            (label cont2)
            (store (iadd i 1) *i)
            (jmp loop-header)
            (label ret-true)
            (ret (trunc 1 i1))
            (label ret-false)
            (ret (trunc 0 i1))
          )
        )
      )
      (let @llvm-mode get-mode)
      (@for-items (quote i) (quote 4 8 16 32 64)
        (set-mode @llvm-mode
          (gen-strcmp i)
        )
      )

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
        (puts (format tmp_buf "equal-strings 1: %i"
          (zext (call strcmp-32
"first_string0934first_string0934
first_string0934first_string0934
first_string0934first_string0934"

"first_string0934first_string0934
first_string0934first_string0934
first_string0934first_string0934"
          64) i32))
        )(putnl)
        (puts (format tmp_buf "equal-strings 2: %i"
          (zext (call strcmp-32 "first_string0934" "first_string1934" 32) i32))
        )(putnl)
        (for-range i 0 10
          (let c (load *c))
          (let c (fadd c c))
          (store c *c)
          (let N 4)
          (print-vector tmp_buf c)
        )
        (ret 0)
      )
    )
  )
)
