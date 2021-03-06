# okta-auth-report

This simple java application queries the Okta Events to create a unique login report based on the specified period given.

There are multiple ways to execute the application.  For testing purposes use maven:

open the pom.xml and set parameters to your specific values.

execute: mvn exec:java

Please note that your apikey is exposed in the pom.xml.

The other option is run mvn install to build the application.  This will place an uber jar in the target folder.  Copy this file to any location and run:

java -jar {application}.jar --oktaorg https://youroktaorg --apikey {your apikey} --startDate YYYY-MM-DDTHH:MM:SS.sssZ --endDate YYYY-MM-DDTHH:MM:SS.sssZ

If you remove --apikey, the application will prompt for you to enter.
After execution the folder where the application is ran will contain two files.

1. [oktaorg]-YYYYMMDDHHMM.txt is a csv report with the following data:
  * Login -- the login id of the user
  * \# of unique authentications -- number of unique authentications on a per user 24 hour basis
  * \# of Authentications -- Number of authentications performed by the user during the time specified
  * Source -- The source of authentication.

Example:

| Login            | # of unique auths  | #of Authentications   | Source          |
| ---------------- |:-----------------: |:---------------------:| --------------- |
| "user1@email.com"|"1"                 |"5"                    | "MYIDP"         |
| "user2@email.com"|"2"                 |"10"                   | "DIFFERENTIDP"  |

2. [oktaorg]-YYYYMMDDHHMM.txt is a csv report with the following data:
  * Login
  * Date
  * Source
  
Example:

| Login            | Date                        | Source         |
| ---------------- |:---------------------------:|:---------------| 
| "user1@email.com"|2017-09-25T11:27:16.000-0400 |"MYIDP"         |
| "user2@email.com"|2017-09-25T11:27:16.000-0400 |"DIFFERENTIDP"  |
  
## Java Requirements
Java 8 or greater is required to execute the application.  The recommended java memory options are:

-Xms512M and -Xmx1G  
 
