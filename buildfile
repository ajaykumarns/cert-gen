# Generated by Buildr 1.3.5, change to your liking
# Version number for this release
Buildr.settings.build['scala.version'] = "2.8.0.RC7"
require 'buildr/scala'
require 'buildr/java/commands' 
VERSION_NUMBER = "1.0.0"
# Group identifier for your projects
GROUP = "cert-generation"
COPYRIGHT = "GPL"

# Specify Maven 2.0 remote repositories here, like this:
repositories.remote << "http://www.ibiblio.org/maven2/"

BOUNCYCASTLE = group('bcprov-jdk16', 'bcpg-jdk16', :under=>'org.bouncycastle', :version=>'1.44')
LOG4J = 'log4j:log4j:jar:1.2.14'
SLF4J = ['org.slf4j:slf4j-api:jar:1.5.8', 'org.slf4j:slf4j-log4j12:jar:1.4.2']

Project.local_task :main
Project.local_task :cli
Project.local_task :reflection
desc "The Cert-generation project"
define "cert-generation" do

  project.version = VERSION_NUMBER
  project.group = GROUP
  manifest["Implementation-Vendor"] = COPYRIGHT
  resources
  test.resources
  #compile.using :make => :transitive
  compile.with BOUNCYCASTLE,LOG4J,SLF4J
  package :jar
  dependencies = compile.dependencies.clone \
                  .add("target/cert-generation-#{VERSION_NUMBER}.jar") \
                  .join(File::PATH_SEPARATOR)
  task :main do
    system "java -cp #{dependencies} com.redhat.certgen.Main"
  end

  task :cli do
    system "java -cp #{dependencies} com.redhat.certgen.CLI #{ENV['path']}"
  end

  task :reflection do
    system "java -cp #{dependencies} com.redhat.certgen.Reflection"
  end
end
