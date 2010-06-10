import java.security._
import java.security.cert._
import org.bouncycastle.x509._
import org.bouncycastle.x509.extension._
import org.bouncycastle.openssl._
import org.bouncycastle.asn1._
import org.bouncycastle.jce._
import java.io._
import java.util.Date
import scala.collection._
import  org.bouncycastle.asn1.x509._
object Utils{

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

case class DateRange(startDate: Date, endDate: Date)
case class KeyAndCertificate(key: PrivateKey, certificate: X509Certificate)
case class X509Extn(oid: String, critical: Boolean, asn1Encodable: ASN1Encodable)

object CertificateGenerationUtils{
  import Utils.implicits._
  import org.bouncycastle.asn1.x509.KeyUsage._
  import org.bouncycastle.asn1.misc._
  import java.util.UUID.randomUUID
  import Utils.implicits._
  lazy val keyFactory  = createRSAKeyFactory
  
  def createRSAKeyFactory = {
    val generator = java.security.KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048)
    generator
  }
  
  def createX509Cert(principal: String, dtRange: DateRange, pbKey: PublicKey,
		     keyCert: Option[KeyAndCertificate], extensions: Option[mutable.Buffer[X509Extn]]): X509Certificate = {
    
    val gen = new org.bouncycastle.x509.X509V3CertificateGenerator()
    gen.setSerialNumber(new java.math.BigInteger("" + Math.abs(new java.util.Random().nextInt)))
    gen.setNotBefore(dtRange.startDate)
    gen.setNotAfter(dtRange.endDate)
    gen.setSubjectDN(new X509Principal(principal))
    gen.setPublicKey(pbKey)
    gen.setSignatureAlgorithm("SHA1WITHRSA")
    
    gen.addExtension(MiscObjectIdentifiers.netscapeCertType.toString(),
		     false, new NetscapeCertType(NetscapeCertType.sslClient | NetscapeCertType.smime))
    gen.addExtension(X509Extensions.KeyUsage.toString(), false,
		     new KeyUsage( digitalSignature | keyEncipherment | dataEncipherment))
    gen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
		     new SubjectKeyIdentifierStructure(pbKey))
    extensions match {
      case Some(exs) => exs.foreach {e:X509Extn => gen.addExtension(e.oid, e.critical, e.asn1Encodable) }  
      case None =>
    }
    keyCert match {
      case Some(kc) =>  
        gen.setIssuerDN(kc.certificate.getSubjectX500Principal)
      gen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
		       new AuthorityKeyIdentifierStructure(kc.certificate))
      return gen.generate(kc.key)
      case None =>
        gen.setIssuerDN(new X509Principal(principal))
      
      return gen.generate(keyFactory.generateKeyPair.getPrivate)
    }
  }
  
  def createDN(consumerName: String, usrName: String, uuid: String) = 
    String.format("CN=%s, UID=%s, OU=%s", consumerName, usrName, uuid)
  
  def createRandomDN = createDN(randomUUID.toString, randomUUID.toString, randomUUID.toString)
  def createRandomX509CertAndKey: KeyAndCertificate = {
    val keyPair = keyFactory.generateKeyPair 
    
    KeyAndCertificate(keyPair.getPrivate, 
		      createX509Cert(createRandomDN, new DateRange(new Date, (new Date).oneYearAhead), 
				     keyPair.getPublic, None, None))
  }
  
  trait X509ExtnSupport{
    val redhatOID = "1.3.6.1.4.1.2312.9"
    def namespace:String
    def + (ex: String, value: String) : X509ExtnSupport = {
      bufr += X509Extn(namespace + "." + ex, false, value)
      return this
    }
    private val bufr = new mutable.ArrayBuffer[X509Extn]
    def toX509Extn: mutable.Buffer[X509Extn] = bufr
  }


  case class Product(hash: Int, name: String, variant: String, arch: String, version: String) 
       extends X509ExtnSupport{
	 override val namespace = "1.3.6.1.4.1.2312.9." + hash 
	 this + (1, name) + (2, variant) + (3, arch) + (4, version)
       }

  case class System(uuid: String, hostUUID: String){
    def this(uuid: String) = this(uuid, null)
    def toX509Extn: mutable.Buffer[X509Extn] = 
      new mutable.ArrayBuffer[X509Extn] +  X509Extn("1.3.6.1.4.1.2312.9.5", false, uuid)
  }

  case class Order(name: String, orderNo: Int, dRange: DateRange, cNo: Int, qUsed: Int, quantity: Int)
     extends X509ExtnSupport{
    override val namespace = "1.3.6.1.4.1.2312.9.4"
    this + (1, name) + (2, orderNo) + (5, quantity) + (6, dRange.startDate) + (7, dRange.endDate) + (12, cNo) + (13, qUsed)
    
  }
  case class Content(id: String, _type: String, name: String, labl: String, vendor: String, contentUrl: String, gpgUrl: String, enabled: Boolean)
       extends X509ExtnSupport{
     override val namespace = redhatOID + ".2." + id + "." + (if(_type.toLowerCase == "yum") 1 else 2)
	 
     this + (1, name) + (2, labl) + (5, vendor) + (6, contentUrl) + (7, gpgUrl) + (8, enabled)
	 
  }

}


object Main extends Application{
  import Utils.implicits._
  import CertificateGenerationUtils._
  def yrDtRange = DateRange(new Date, (new Date).oneYearAhead)
  val kc = CertificateGenerationUtils.createRandomX509CertAndKey
  println(new String(kc.key))
  println(new String(kc.certificate))
  val keyPair = keyFactory.generateKeyPair 
  val extensions:mutable.Buffer[X509Extn] = new mutable.ArrayBuffer[X509Extn]
  (extensions ++ Order("Red Hat ENterprise Linux Server", 12345, yrDtRange, 152341643, 4, 100).toX509Extn 
    ++ new System(java.util.UUID.randomUUID.toString).toX509Extn ++ Product(8251, "Red Hat Enterprise Linux", "Server", "x86_64", "6.0").toX509Extn 
    ++ Content(789, "yum", " Red Hat Enterprise Linux (Supplementary)", 
		 "rhel-server-6-supplementary", "%Red_Hat_Id% or %Red_Hat_Label%", "content/rhel-server-6-supplementary/$releasever/$basearch", "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release", true).toX509Extn);
  val kc1 = KeyAndCertificate(keyPair.getPrivate, 
		      createX509Cert(createRandomDN, yrDtRange, 
				     keyPair.getPublic, None, Some(extensions)))
  "/home/ajay/tmp/key.pem" << kc1.key
  "/home/ajay/tmp/cert.pem" << kc1.certificate
}
