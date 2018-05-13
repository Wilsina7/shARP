#! /bin/bash 

arg=$1       #This is the first command line argument
mode=$2      #This is the second command line argument
interface=$3 #This is the third command line argument

#Run ip route command and extract gateway from its output
#First run ip route and filter the output to keep only the line that has "default"
#This will give something like "default via 10.10.10.1 dev eth0

gateway=`ip route | grep default`

#Now remove all characters before "via" from the gateway string
#This will give something like "10.10.10.1 dev eth0"

gateway=${gateway##*via}

#Now remove all characters after “dev” from the gateway string
#This will give “10.10.10.1”

gateway=${gateway%dev*}

#This is wrong logic and will never execute because -z checks if the string is null or 
#zero length which will never happen because there are spaces around $interface. So 
#even if $interface is empty the string will be “  “
#So, this can be removed


if [ ! -z " $interface " ];then
	channel=`iwlist $interface channel`
	channel=${channel%)*}
	channel=${channel##*l}
fi

#If first command line argument arg is -r or –reset then reset the interface and 
#restart the network manager service

if [ " $arg " = ' -r ' ] || [ " $arg " = ' --reset ' ]; then
	interfacemon=$interface'mon'
	airmon-ng stop $interfacemon ; 
	ifconfig $interface down ; 
	ifconfig $interface up ;
	service network-manager restart ; 
	sleep 5
#===========================
# Defensive mode starts here
#===========================
#will check if defensive mode
03.0
elif [ " $arg " = ' -d ' ] || [ " $arg " = ' --defence ' ]; then
	
	#ping gateway and save the output in gtping 
	
	gtping=`ping $gateway -c 1` 
	
	#The $gateway Ip Address shows up 4 times in the ping output if ping is successful
	#Hence, remove all characters after the gateway ip address 4 times 

	gtping=${gtping%$gateway*} #retain the part before gateway
	gtping=${gtping%$gateway*} #retain the part before gateway
	gtping=${gtping%$gateway*} #retain the part before gateway
        gtping=${gtping%$gateway*} #retain the part before gateway
	
	#In the end only the string “PING” will be left in gtping
 	
	if [ " $gtping " = " PING " ] ; then
	
	#Get arp table information for the given interface and store it in MYVAR
	#It will look as follows:
	#“Address HWtype HWaddress Flags Mask Iface gateway ether 02:42:28:31:0a:a8 C eth0”

  		MYVAR=`sudo arp $gateway -i $interface `
  		add=${MYVAR%C*}  #keep everything before the C
  		add=${add##*r}  #keep everything after ether
		
		#Create /usr/shARP/ directory if is does not exist and create gateway.txt file in it
		
  		if [  /usr/shARP/ = false ] && [ /usr/shARP/ != true ]; then
  			 sudo mkdir /usr/shARP 
  		fi 
		mkdir -p /usr/shARP/
		touch /usr/shARP/gateway.txt
  		echo  $(date +"%D") ": DEFENSIVE MODE : The original address of the gateway is " $add >> /usr/shARP/gateway.txt
  		arp $gateway -i $interface
		arpout=`arp $gateway -i $interface`
  		echo .................................................
  		
		#Add the gateway to arpd and then save the same value to anothe variable carpd
		
		arpd=$add
  		carpd=$arpd
  		carpd=${carpd//[ ]/}
  		vendor=${carpd//[:]/}
		vendor=${vendor:0:6}
		#get the MacId and compare if it is same as Vendor ID, if yes display message saying 
		# details about the current gateway and Mac Vendoe
  		while read line
		do macid=${line:0:6}
			vendor="${vendor^^}"
			if [ " $macid " = " $vendor " ]
			then 
				echo "Your current gateway is " $add " and your MAC Vendor is " ${line:(+6)}
			fi	       
		done < mac-vendors.txt	#End of while loop
  		echo ......................................... 
		 #==================
		 # Defensive-active
		 #==================
		 #This part will ccheck if active mode, if yes then it will continues keep checking 
		 #for any changes in routing table
		if [ " $mode " = ' -a ' ] || [ " $mode " = "--active " ];then  

			while true
			do	
			# this part will continuosly check routing table,
			#get the Mac address and save it in carpd variable
			
				output=`sudo arp $gateway -i $interface`
				carpd=${output%C*}  # delete the part after the C
				carpd=${carpd##*r}  # delete the part before the ether
				arpd=${arpd//[ ]/}
				carpd=${carpd//[ ]/}
				
				#this part will compare the new Mac address with the initially stored address
				#if they are not equal then there is an attack happening and it will warn the user
			
				if [ " $arpd " != " $carpd " ]; then
					echo "Gateway changed from " $arpd " to " $carpd " at time " $(date +"%T") 
					echo $carpd "is spoofing!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! "
  					echo "network connection going down "
					#shutdown the network
					ifconfig $interface down
					
                        	        vendor=${carpd//[:]/}
                        	        vendor=${vendor:0:6}
                        	        while read line
				      	do 
					#this part will tell what is the Mac address of the vendor and diplay it
						macid=${line:0:6}
						vendor="${vendor^^}"
						if [ " $macid " = " $vendor " ]
						then 
							echo "MAC Vendor of the attacker is " ${line:(+6)}
							macvendor=${line:(+6)}
						fi
				        done < mac-vendors.txt
					#will save the attacker Mac address to vendors.txt file and exit
					echo "Gateway changed from" $arpd " to" $carpd " at time " $(date +"%T") " on " $(date +"%D") "The attacker's MAC vendor is " $macvendor >> /usr/shARP/log.txt  
					espeak  'network is being spoofed by '$carpd', connection, going down. Contact your network administrator.' 
					exit         
				fi ; 
			done; 
	 	
	 #==================
	 # Defensive-passive
	 #==================
   	 elif [ " $mode " = ' -p ' ] || [ " $mode " = " --passive " ];then
   	 # this mode will find out the attacker mac address by using mac-decoder code if it find there that the 
	 #Mac address has been changed it will simultaneously call passive.sh and will work on the attack without l
	 #letting the user data speed get affected
	 #not found will display gateway not found
   	 	mymac=`ifconfig $interface`
   	 	mymac=${mymac%tx*}
   	 	mymac=${mymac##*ether}
   	 	 
   	 	python mac_decoder.py $mymac $arpd $interface $arg
   	fi
   	else echo "Gateway not found"
        fi
#=================================================
# Defensive mode ends here
#=================================================
# Offensive mode starts here
#=================================================
elif [ " $arg " = ' -o ' ] || [ " $arg " = ' --offence ' ]; then 

	#Ping the gateway and store the output in gtping
	gtping=`ping $gateway -c 1`
	
	#The $gateway Ip Address shows up 4 times in the ping output if ping is successful
	#Hence, remove all characters after the gateway ip address 4 times
	gtping=${gtping%$gateway*} #retain the part before gateway
	gtping=${gtping%$gateway*} #retain the part before gateway
	gtping=${gtping%$gateway*} #retain the part before gateway
	gtping=${gtping%$gateway*} #retain the part before gateway
	#In the end only the string “PING” will be left in gtping
	
	#==============================
	# If gateway is found successfully
	#==============================
   	if [ " $gtping " = " PING " ] ; then 
		
		#Get arp table information for the given interface and store it in MYVAR
		#It will look as follows:
		#“Address HWtype HWaddress Flags Mask Iface gateway ether 02:42:28:31:0a:a8 C eth0”
		output=`sudo arp $gateway -i $interface `
		add=${output%C*}  # retain the part before the C
		add=${add##*r}  # retain the part after the ether


		mkdir -p /usr/shARP/
		touch /usr/shARP/gateway.txt

		echo $(date +"%D") " : OFFENSIVE MODE : The original address of the gateway is " $add >> /usr/shARP/gateway.txt
		arp $gateway -i $interface
		echo ..........................................
		arpd=$add
		carpd=$arpd
		carpd=${carpd//[ ]/} 
		vendor=${carpd//[:]/}
		vendor=${vendor:0:6}
		while read line
		do 
			macid=${line:0:6}
		   	vendor="${vendor^^}"
		       	if [ " $macid " = " $vendor " ]
			then 
			 	echo "Your current gateway is " $add " and your MAC Vendor is " ${line:(+6)}     
		       	fi	       
		done < mac-vendors.txt
  
   		echo ....................................... 
		
		#=============================
		# Offensive-active
		#=============================
		#will check if offensive mode
	 	if [ " $mode " = ' -a ' ] || [ " $mode " = "--active " ];then  
			while true
			do
				MYVAR=`sudo arp $gateway -i $interface`

				carpd=${MYVAR%C*}  # retain the part after the C
				carpd=${carpd##*r}  # retain the part before the ether
				arpd=${arpd//[ ]/}
				carpd=${carpd//[ ]/}

				if [ " $arpd " != " $carpd " ]; then 
					echo "Gateway changed from " $arpd " to " $carpd " at time " $(date +"%T") 
					echo $carpd "is spoofing!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! "
					echo "network connection going down "

					vendor=${carpd//[:]/}
					vendor=${vendor:0:6}
					while read line
					do 
						macid=${line:0:6}
						if [ " $macid " = " $vendor " ]
						then 
							echo "MAC Vendor of the attacker is " ${line:(+6)} 
							macvendor=${line:(+6)}                                       
						fi
				       done < mac-vendors.txt

					echo "Gateway changed from " $arpd " to " $carpd " at time " $(date +"%T") " on " $(date +"%D") "The attacker's MAC vendor is " $macvendor >> /usr/shARP/log.txt 
					#aircrack-ng and airmon-ng are the tools available online which will start and Dos attack
					#on the attacker and disable it
					hash aircrack-ng >> /usr/shARP/hash1.txt 
					hash airmon-ng >> /usr/shARP/hash2.txt 
					r1hash=$(cat /usr/shARP/hash1.txt)
					r2hash=$(cat /usr/shARP/hash2.txt)
					if [ " $r2hash " = "bash: hash: airmon-ng: not found" ] || [ " $r1hash " = "bash: hash: aircrack-ng: not found" ] ;then
						#we install aircrack-ng
						sudo apt-get install aircrack-ng
						#start tha airmon-ng and aircrack-ng
						echo "airmon-ng and aircrack-ng are starting"
					else 
						echo "airmon-ng and aircrack-ng are starting"
					fi
					sudo airmon-ng start $interface
					sudo airmon-ng check kill
					sudo airmon-ng start $interface'mon' $channel 
					while true 
					do 
						sudo aireplay-ng -0 1000 -a $arpd -c $carpd $interface'mon' 
					done
					exit
				fi
 	      		done
		#=============================
		# Offensive-passive
		#=============================
	 	elif [ " $mode " = ' -p ' ] || [ " $mode " = " --passive " ];then
		#will do similary as in defensive mode
   	 
   	 		mymac=`ifconfig $interface`
   	 		mymac=${mymac%tx*}
   	 		mymac=${mymac##*ether}
   	 	 #will do similary as in defensive mode
   	 		python mac_decoder.py $mymac $arpd $interface $arg
    	 	fi 
	#=======================
	# Gateway not found
	#=======================
	else 
		echo "Gateway not found" ;
	fi
	
#==============================
 

