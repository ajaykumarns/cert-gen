package com.redhat.certgen
import scala.collection.mutable
import java.security._
import java.security.cert._
/**
 * Created by IntelliJ IDEA.
 * User: ajay
 * Date: Jun 18, 2010
 * Time: 4:53:49 PM
 * To change this template use File | Settings | File Templates.
 */

object ExtensionSupport extends LoggerSupport{
  object namespace{
    val rh = "1.3.6.1.4.1.2312.9"
    val product = rh + ".1"
    val content = rh + ".2"
    val role = rh +".3"
    val order = rh + ".4"
    val system = rh + ".5"
  }

  type ExtensionProvider = {def getExtensionValue(str: String): Array[Byte]}
  implicit def stripRh(str: String) = new {
    def stripRhExtension = str.substring(namespace.rh.length + 1)
  }

  trait TrieNode extends{
    import org.bouncycastle.asn1._
    val parent: TrieNode
    def identifier: String = ""
    private var _children: Option[mutable.Map[String, TrieNode]] = None
    def children: Option[mutable.Map[String, TrieNode]] = _children
    def addChild(identifier: String) : TrieNode = {
      _children match {
        case None => _children = Some(new mutable.HashMap)
        addChild(identifier)
        case Some(map) => if(!map.contains(identifier)) map(identifier) = new Node(identifier, this)
      }
      return this
    }

    def addExtension(l: List[String]) {
      l match {
        case head :: tail =>
          this.addChild(head)
          this.children match {
            case Some(map) => map(head).addExtension(tail)
            case None =>
          }
        case Nil =>
      }
    }

    lazy val fullExtension:String = parent.fullExtension + "." + identifier
    def isChild = _children == None
    def isParent = !(isChild)
    def extensionProvider: ExtensionProvider = parent.extensionProvider
    def value =
      new ASN1InputStream(
        new ASN1InputStream(extensionProvider.getExtensionValue(fullExtension))
                  .readObject.asInstanceOf[DEROctetString].getOctets).readObject.toString
    
    protected def _locate(parentNode: TrieNode, extensions: List[String]): Option[TrieNode] = {
      logger.debug(parentNode.children.mkString("\n") + "extensions : " + extensions)
      extensions match {
        case head :: tail =>
          //println("head: "+ head + parentNode.children.get.get(head) + "\n" + parentNode.children.get)
          parentNode.children match {
            case Some(map) if map.contains(head)=> _locate(map(head), tail)
            case None | _ => None
          }
        case Nil => Some(parentNode)
      }
    }

    def locateChild(ex: String) : Option[TrieNode] = {
      val rest = ex.substring(fullExtension.length +1)
      logger.debug("locating Child : " +  ex)
      _locate(this, ex.substring(fullExtension.length +1).split("\\.").toList)
    }

    def \ (ex: String): Option[TrieNode] = locateChild(ex)

    def noOfChildren: Int = _children match {
      case Some(map) => map.size
      case None => 0
    }
    override def toString = "[TrieNode] " + fullExtension + " children #" + noOfChildren
  }

  object EmptyNode extends TrieNode{
    override lazy val fullExtension: String = ""
    override val parent: TrieNode = null
  }

  class RedHatNode(override val extensionProvider: ExtensionProvider) extends TrieNode{
    override val identifier = namespace.rh
    override val parent : TrieNode = EmptyNode
    override lazy val fullExtension:String = identifier
  }

  class Node(override val identifier: String, override val parent: TrieNode) extends TrieNode

  object RedHatNode{
    def toTrie(cert: X509Certificate): RedHatNode= {
      val redhatNode = new RedHatNode(cert)
      logger.debug("total no of extensions : " + cert.getNonCriticalExtensionOIDs.size)
      cert.getNonCriticalExtensionOIDs.toArray.asInstanceOf[Array[Object]].map(_.asInstanceOf[String])
                .filter(_.indexOf(namespace.rh) != -1)
                .foreach { ex: Object =>
        val str = ex.asInstanceOf[String].stripRhExtension
        logger.debug("Adding extension : " + ex + " | str :" + str + " | " + str.split("\\.").mkString(","))
        redhatNode.addExtension(str.split("\\.").toList)
      }
      return redhatNode
    }

    def apply(cert: X509Certificate): RedHatNode = toTrie(cert)
  }
}
