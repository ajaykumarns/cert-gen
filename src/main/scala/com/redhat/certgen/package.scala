//package com.redhat.certgen

package object certgen{
  //type mutable = scala.collection.mutable
  import org.slf4j.LoggerFactory
  def loggerFor(clas: Class[_]) = LoggerFactory.getLogger(clas)
}

