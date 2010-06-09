import java.security._
import java.security.cert._
import org.bouncycastle.x509._
import org.bouncycastle.x509.extension._
import org.bouncycastle.openssl._
import java.io._

object Utils{
    def toBytes(obj: Any) : Array[Byte] = {
      val byteOut = new ByteArrayOutputStream
      val out = new PEMWriter(new OutputStreamWriter(byteOut))
      out.writeObject(obj)
      out.close
      byteOut.toByteArray
    }
    object implicits{
      implicit def x509ToBytes(cert: X509Certificate) = new {
        def toPemBytes: Array[Byte] = toBytes(cert)
      }
      
      implicit def keyToBytes(key: Key) = new {
        def toPemBytes: Array[Byte] = toBytes(key)
      }
    }
}


object CertificateGenerationUtils{
  import Utils.implicits._
  
  
}

