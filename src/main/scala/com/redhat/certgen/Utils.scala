package com.redhat.certgen

import org.bouncycastle.openssl.PEMWriter
import org.bouncycastle.asn1.{DERUTF8String, ASN1Encodable}
import java.io.{OutputStreamWriter, ByteArrayOutputStream}
import java.util.Date
import java.security.Key
import java.security.cert.X509Certificate

/**
 * Created by IntelliJ IDEA.
 * User: ajay
 * Date: Jun 18, 2010
 * Time: 4:56:50 PM
 * To change this template use File | Settings | File Templates.
 */
trait LoggerSupport{
  val logger = Utils.loggerFor(getClass)
}
object Utils{
  def loggerFor(clas: Class[_]) = org.slf4j.LoggerFactory.getLogger(clas)
  def toBytes(obj: Any) : Array[Byte] = {
    val byteOut = new ByteArrayOutputStream
    val out = new PEMWriter(new OutputStreamWriter(byteOut))
    out.writeObject(obj)
    out.close
    byteOut.toByteArray
  }

  object implicits{
    implicit def strToDerUtf8Str(str: String): ASN1Encodable = new DERUTF8String(str)
    implicit def intToStr(i: Int): String = String.valueOf(i)
    implicit def strToInt(str: String): Int = Integer.parseInt(str)
    implicit def dateToStr(d: Date): String = d.toString
    implicit def boolToInt(b: Boolean): Int = if(b) 1 else 0
    implicit def boolToStr(b: Boolean): String = if(b) "1" else "0"
    implicit def xCertToBytes(cert: X509Certificate): Array[Byte] = toBytes(cert)
    implicit def imKeyToBytes(key: Key): Array[Byte] = toBytes(key)
    implicit def dumpByteIntoFile(str: String) = new {
      def << (bytes: Array[Byte]) = writeToFile(str, bytes)
    }
    implicit def x509ToBytes(cert: X509Certificate) = new {
      def toPemBytes: Array[Byte] = toBytes(cert)
    }

    implicit def keyToBytes(key: Key) = new {
      def toPemBytes: Array[Byte] = toBytes(key)
    }                                          

    implicit def exDate(d: java.util.Date) = new {
      import java.util.Calendar
      def oneYearAhead = {
        val cal = Calendar.getInstance();
        cal.setTime(d)
        cal.set(Calendar.YEAR, cal.get(Calendar.YEAR) + 1)
        cal.getTime
      }
    }
  }
  type Closable = {def close(): Unit}
  def safeExecute[B <: Closable](closable: B, func: (B) => Unit){
    try{
      func(closable)
    }finally{
      closable.close
    }
  }

  def writeToFile(filePath: String, contents: Array[Byte]){
    import java.io._
    val out = new FileOutputStream(filePath)
    safeExecute(out, { o: OutputStream => o.write(contents) })
  }
}
