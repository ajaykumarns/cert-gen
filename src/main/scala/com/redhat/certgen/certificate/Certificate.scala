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
import com.redhat.certgen.Utils.implicits._

@scala.reflect.BeanInfo class Certificate{
  import com.redhat.certgen.ExtensionSupport._
  import com.redhat.certgen.editor._
  @UseEditor(editor=classOf[MultiElementsEditor])
  @CertificateType(category="Content")
  val contents:mutable.Buffer[GenericCertificateEntity] = new mutable.ArrayBuffer

  @UseEditor(editor=classOf[MultiElementsEditor])
  @CertificateType(category="Role")
  val roles: mutable.Buffer[GenericCertificateEntity] = new mutable.ArrayBuffer

  @CertificateType(category="System")
  var system: Option[GenericCertificateEntity] = None

  @CertificateType(category="Order")
  var order: Option[GenericCertificateEntity] = None

  @UseEditor(editor=classOf[MultiElementsEditor])
  @CertificateType(category="Product")
  val products: mutable.Buffer[GenericCertificateEntity] = new mutable.ArrayBuffer

  var startDate = new Date()
  var endDate = (new Date()).oneYearAhead
  var serial = new java.math.BigInteger(new java.util.Random().nextInt)
  var publicKey: PublicKey = _
  var subjectDN = CertificateGenerationUtils.createDN()

  @UseEditor(editor=classOf[StringMapEditor])
  val customExtensions: Map[String, String] = new mutable.HashMap
  override def toString = {
    val bufr = new StringBuilder
    bufr.append("\n|Certificate|\n beginDate = ")
    .append(startDate).append(", endDate = ").append(endDate)
    .append("\nSerial = ").append(serial)
    if(contents.size > 0) bufr.append(contents.mkString("\n|Contents|\n", "\n", "\n------------\n"))
    if(roles.size > 0)    bufr.append(roles.mkString("\n|Roles|\n", "\n", "\n------------\n"))
    if(system != None)    bufr.append(system.get.toString).append("\n")
    if(order != None)     bufr.append(order.get.toString).append("\n")
    if(products.size > 0) bufr.append(products.mkString("\n|Products|\n", "\n", "\n------------\n"))
    bufr.toString
  }
}


object Certificate{
  import com.redhat.certgen.ExtensionSupport._
  def apply(cert: X509Certificate) = {
    val certificate = new Certificate
    val rhTrie = RedHatNode(cert)
    println("Order : " + namespace.order)
    certificate.order = GenericCertificateEntity('Order, rhTrie \ namespace.order)
    certificate.system = GenericCertificateEntity('System, rhTrie \ namespace.system)
    certificate.startDate = cert.getNotBefore
    certificate.endDate = cert.getNotAfter
    certificate.serial = cert.getSerialNumber
    certificate.publicKey = cert.getPublicKey
    certificate.subjectDN = cert.getSubjectDN.toString
    rhTrie \ namespace.product match {
      case Some(node) if node.children != None =>
        for(product <- node.children.get){
          certificate.products += GenericCertificateEntity('Product, product._2)
        }
      case None | _ =>
    }

    rhTrie \ namespace.content match { //content namespace level
      case Some(node) if node.children != None =>
        for(content <- node.children.get){ //content hash level.
          for(child <- content._2.children.get){  //for same content, there could be more than single repo type
            certificate.contents += GenericCertificateEntity('Content, child._2)
          }
        }
      case None | _ =>
    }

    rhTrie \ namespace.role match {
      case Some(node) if node.children != None =>
        for(role <- node.children.get){
          certificate.roles += GenericCertificateEntity('Role, role._2)
        }
      case None | _ =>
    }
    certificate
  }

  def toX509(cert: Certificate, keyCert: Option[KeyAndCertificate] = None): X509Certificate = {
    import GenericCertificateEntity.toExtensions
    val extensions: mutable.Buffer[X509Extn] = new mutable.ArrayBuffer
    extensions ++= toExtensions(cert.contents) ++= toExtensions(cert.roles) ++= toExtensions(cert.products)
    cert.system match{ case Some(system) => extensions ++= toExtensions(system); case None => }
    cert.order match{ case Some(order) => extensions ++= toExtensions(order); case None => }
    extensions ++= cert.customExtensions.iterator.map(e => X509Extn(e._1, false, e._2))
    CertificateGenerationUtils.createX509Cert(principal = new X500Principal(cert.subjectDN), dtRange = DateRange(cert.startDate, cert.endDate),
		   serial = cert.serial, pbKey = cert.publicKey, keyCert = keyCert, extensions = Some(extensions))
  }
}
