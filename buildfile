# Generated by Buildr 1.3.5, change to your liking
# Version number for this release
require 'buildr/scala'
require 'buildr/java/commands' 
ENV['SCALA_HOME'] = '/opt/scala'
VERSION_NUMBER = "1.0.0"
# Group identifier for your projects
GROUP = "cert-generation"
COPYRIGHT = ""

# Specify Maven 2.0 remote repositories here, like this:
repositories.remote << "http://www.ibiblio.org/maven2/"
BOUNCYCASTLE = group('bcprov-jdk16', 'bcpg-jdk16', :under=>'org.bouncycastle', :version=>'1.44')
Project.local_task :main
desc "The Cert-generation project"
define "cert-generation" do

  project.version = VERSION_NUMBER
  project.group = GROUP
  manifest["Implementation-Vendor"] = COPYRIGHT
  resources
  test.resources
  compile.with BOUNCYCASTLE
  package :jar
  puts compile.dependencies.class
  dependencies = compile.dependencies.clone.add("target/classes").join(File::PATH_SEPARATOR)
  task :main => :compile do
    #Java::Commands::java('com.redhat.certgen.Main', { :classpath => compile.dependencies.join(File::PATH_SEPARATOR) })
    system "java -cp #{dependencies} com.redhat.certgen.Main"
  end
end
