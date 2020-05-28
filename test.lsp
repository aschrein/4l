(scope
  (add-mode llvm
    (let float3
      (struct
        (f32 x)
        (f32 y)
        (f32 z)
      )
    )
    (let ray_t
      (struct
        (float3 loc)
        (float3 dir)
        (i32 pixel_i)
        (i32 pixel_j)
      )
    )
    (let sphere_t
      (struct
        (float3 pos)
        (f32 radius)
      )
    )
    (let camera_t
      (struct
        (float3 pos)
        (float3 look)
        (float3 up)
        (float3 right)
        (f32 fov)
        (f32 aspect)
      )
    )
    (let make_float3
      (lambda (x y z)
        (let out (alloca float3))
        (store x (mgep out x))
        (store y (mgep out y))
        (store z (mgep out z))
        out
      )
    )
    (let make_sphere
      (lambda (pos r)
        (let a (alloca sphere_t))
        (store (load pos) (mgep a pos))
        (store r (mgep a radius))
        a
      )
    )
    (let alloca_camera
      (lambda (
          pos
          look
          up
          right
          fov
          aspect
        )
        (let a (alloca camera_t))
        (store (load pos) (mgep a pos))
        (store (load look) (mgep a look))
        (store (load up) (mgep a up))
        (store (load right) (mgep a right))
        (store fov (mgep a fov))
        (store aspect (mgep a aspect))
        a
      )
    )
    (module
;;      (function void make_float3
;;                     (
;;                       ((pointer float3) out)
;;                       (f32 x)
;;                       (f32 y)
;;                       (f32 z)
;;                     )
;;        (store x (mgep out x))
;;        (store y (mgep out y))
;;        (store z (mgep out z))
;;        (ret)
;;      )
      (function i32 main
                     (
                      (i32 argc)
                      ((pointer (pointer i8)) argv)
                     )
        (let put-rgb
          (lambda (r g b)
            (call ll_fputchar f r)
            (call ll_fputchar f g)
            (call ll_fputchar f b)
          )
        )
        (let s1 (make_sphere (make_float3 0.0 0.0 0.0) 1.0))
        (let a  (make_float3 777.0 1.0 2.0))
        (let b  (make_float3 55.0 1.0 2.0))
        (let cam
          (alloca_camera
            (make_float3 0.0 0.0 2.0) ; pos
            (make_float3 0.0 0.0 -1.0) ; look
            (make_float3 0.0 1.0 0.0) ; up
            (make_float3 1.0 0.0 0.0) ; right
            1.0 ; fov
            1.0 ; aspect
          )
        )
        (let fmt_buf (alloca (array i8 256)))
        (println (format fmt_buf "%f %f %f"
          (load (mgep b x))
          (load (mgep b y))
          (load (mgep b z))
        ))
        (println (format fmt_buf "%f %f %f"
          (load (mgep a x))
          (load (mgep a y))
          (load (mgep a z))
        ))
        (println (format fmt_buf "camera.pos = %f %f %f"
          (load (mgep (mgep cam pos) x))
          (load (mgep (mgep cam pos) y))
          (load (mgep (mgep cam pos) z))
        ))
        (let f (call ll_fopen "tmp.ppm" "wb"))
        (call ll_fwrite_line f "P6" 2)
        (call ll_fwrite_line f "128 128" 7)
        (call ll_fwrite_line f "255" 3)
;;        (for-range i 0 128
;;          (for-range j 0 128
;;            (put-rgb i j 0)
;;          )
;;        )
        (call ll_fclose f)
        (ret 0)
      )
    )
  )
)
