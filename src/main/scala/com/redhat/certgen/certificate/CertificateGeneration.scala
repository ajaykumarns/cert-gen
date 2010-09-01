package com.redhat.certgen.certificate
import java.security._
import java.security.cert._
import org.bouncycastle.x509.extension._
import org.bouncycastle.asn1._
import org.bouncycastle.jce._
import java.util.Date
import scala.collection._
import org.bouncycastle.asn1.x509._
import javax.security.auth.x500.X500Principal
import java.math.BigInteger
import com.github.certgen.annotations._
case class DateRange(startDate: Date, endDate: Date)
case class KeyAndCertificate(key: PrivateKey, certificate: X509Certificate)
case class X509Extn(oid: String, critical: Boolean, asn1Encodable: ASN1Encodable)

object CertificateGenerationUtils{
  import com.redhat.certgen.Utils.implicits._
  import org.bouncycastle.asn1.x509.KeyUsage._
  import org.bouncycastle.asn1.misc._
  import java.util.UUID.randomUUID
  lazy val keyFactory  = createRSAKeyFactory
  val currentDateRange = DateRange(new Date(), (new Date()).oneYearAhead)
  def createRSAKeyFactory = {
    val generator = java.security.KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048)
    generator
  }

  def createX509Cert(principal: X500Principal = new X500Principal(createDN()),
		     dtRange: DateRange = currentDateRange, 
		     serial:BigInteger = new BigInteger("" + scala.math.abs(new java.util.Random().nextInt)),
                     pbKey: PublicKey, keyCert: Option[KeyAndCertificate] = None,
                     extensions: Option[Iterable[X509Extn]] = None): X509Certificate = {

    val gen = new org.bouncycastle.x509.X509V3CertificateGenerator()
    gen.setSerialNumber(serial)
    gen.setNotBefore(dtRange.startDate)
    gen.setNotAfter(dtRange.endDate)
    gen.setSubjectDN(principal)
    gen.setPublicKey(pbKey)
    gen.setSignatureAlgorithm("SHA1WITHRSA")

    gen.addExtension(MiscObjectIdentifiers.netscapeCertType.toString(),
		     false, new NetscapeCertType(NetscapeCertType.sslClient | NetscapeCertType.smime))
    gen.addExtension(X509Extensions.KeyUsage.toString(), false,
		     new KeyUsage( digitalSignature | keyEncipherment | dataEncipherment))
    gen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
		     new SubjectKeyIdentifierStructure(pbKey))
    extensions match {
      case Some(exs) => exs.foreach {e:X509Extn => gen.addExtension(e.oid, e.critical, e.asn1Encodable) }; println("extensions size : " + exs.size)

      case None =>
    }
    keyCert match {
      case Some(kc) =>
        gen.setIssuerDN(kc.certificate.getSubjectX500Principal)
	gen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
		       new AuthorityKeyIdentifierStructure(kc.certificate))
	return gen.generate(kc.key)
      case None =>
        gen.setIssuerDN(principal)
        return gen.generate(keyFactory.generateKeyPair.getPrivate)
    }
  }


 def createDN(consumerName: String = randomUUID.toString, usrName: String = randomUUID.toString,
               uuid: String = randomUUID.toString) =
    String.format("CN=%s, UID=%s, OU=%s", consumerName, usrName, uuid)

  def createRandomX509CertAndKey: KeyAndCertificate = {
    val keyPair = keyFactory.generateKeyPair

    KeyAndCertificate(keyPair.getPrivate,
		      createX509Cert(pbKey = keyPair.getPublic))
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
      new mutable.ArrayBuffer[X509Extn] += X509Extn("1.3.6.1.4.1.2312.9.5", false, uuid)
  }

  case class Order(name: String, orderNo: Int, dRange: DateRange = currentDateRange, cNo: Int, qUsed: Int, quantity: Int, warningPeriod: Int)
     extends X509ExtnSupport{
    override val namespace = "1.3.6.1.4.1.2312.9.4"
    this + (1, name) + (2, orderNo) + (5, quantity) + (6, dRange.startDate) + (7, dRange.endDate) + (12, cNo) + (13, qUsed) + (14, warningPeriod)

  }
  case class Content(id: String, _type: String, name: String, labl: String, vendor: String, contentUrl: String, gpgUrl: String, enabled: Boolean)
       extends X509ExtnSupport{
     override val namespace = redhatOID + ".2." + id + "." + (if(_type.toLowerCase == "yum") 1 else 2)

     this + (1, name) + (2, labl) + (5, vendor) + (6, contentUrl) + (7, gpgUrl) + (8, enabled)
  }
}

object Main extends Application{
  import com.redhat.certgen.Utils.implicits.{dumpByteIntoFile, imKeyToBytes, intToStr, xCertToBytes}
  import com.redhat.certgen.editor._
  import com.redhat.certgen.DrawUtils.implicits._
  import CertificateGenerationUtils._
  // val kc = CertificateGenerationUtils.createRandomX509CertAndKey
  // println(new String(kc.key))
  // println(new String(kc.certificate))
  val keyPair = keyFactory.generateKeyPair
  val extensions:mutable.Buffer[X509Extn] = new mutable.ArrayBuffer[X509Extn]
  (extensions ++=
          Order(name="Red Hat ENterprise Linux Server", orderNo=12345, cNo=152341643, qUsed=4, quantity=100, warningPeriod=0).toX509Extn
          ++= new System(java.util.UUID.randomUUID.toString).toX509Extn
          ++ Product(8251, "Red Hat Enterprise Linux", "Server", "x86_64", "6.0").toX509Extn
          ++= Content(789, "yum", " Red Hat Enterprise Linux (Supplementary)",
		            "rhel-server-6-supplementary", "%Red_Hat_Id% or %Red_Hat_Label%", "content/rhel-server-6-supplementary/$releasever/$basearch", "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release", true).toX509Extn);


  val kc1 = KeyAndCertificate(keyPair.getPrivate,
		      createX509Cert(pbKey = keyPair.getPublic, extensions = Some(extensions)))
  "/home/ajay/tmp/key.pem" << kc1.key
  "/home/ajay/tmp/cert.pem" << kc1.certificate
 // "/home/ajay/tmp/cert1.pem" << kc.certificate
  val trie = com.redhat.certgen.ExtensionSupport.RedHatNode.toTrie(kc1.certificate)
  val testCert = Certificate(kc1.certificate)

  //println(Certificate.toX509(cert = testCert))
  val editor = CertificateEditor(testCert)
  println(editor.editableFields)
  println(editor.editorFor("startDate").asInstanceOf[SimpleEditor].apply("02/02/2001"))
  println(testCert)
  com.redhat.certgen.ConsoleTreeDrawer.drawTree(testCert.toNode())
}

