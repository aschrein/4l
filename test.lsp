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
    (module
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
        (let a (alloca float3))
        (let a (alloca ray_t))
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
