package com.github.certgen.annotations;
import java.lang.annotation.*;
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface UseEditor{
  Class<?> editor();
}