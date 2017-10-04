package oktareport;

import org.apache.commons.cli.*;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UniqueLoginReport {

    private static String tenantUrl = null;
    private static String token = null;
    private static final Logger logger = LogManager.getLogger(UniqueLoginReport.class);
    private static final Logger reportLog = LogManager.getLogger("loginreport");
    private static final SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");

    private static long HOURS24 = 86400000L;

    private static Pattern linkMatcher = Pattern.compile("^<(.*)>; rel=\"(.*)\"$");

    public static String[] get(String resource, String token) {
        boolean tryAgain = true;
        String result = "";
        String nextUrl = "";
        URL url;
        HttpURLConnection conn;
        BufferedReader rd;
        String line;
        String[] response = new String[2];
        logger.debug("URL = " + resource);
        try {
            url = new URL(resource);
            while (tryAgain) {
                result = "";
                nextUrl = "";
                try {
                    conn = (HttpURLConnection) url.openConnection();
                    conn.setConnectTimeout(10000);
                    conn.setReadTimeout(10000);
                    conn.setRequestProperty("Accept", "application/json");
                    conn.setRequestProperty("Content-Type", "application/json");
                    conn.setRequestProperty("Authorization", "SSWS " + token);
                    conn.setRequestMethod("GET");

                    String ret = conn.getResponseMessage();
                    int retCode = conn.getResponseCode();

                    if (retCode == 200) {
                        tryAgain = false;
                        rd = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
                        while ((line = rd.readLine()) != null) {
                            result += line;
                        }
                        response[0] = result;
                        List<String> links  = conn.getHeaderFields().get("Link");
                        links.forEach( (link) -> {
                            Matcher linkMatch = linkMatcher.matcher(link);
                            if(linkMatch.matches()) {
                                if(linkMatch.group(2).equals("next")) {
                                    response[1] = linkMatch.group(1);
                                }
                            }
                        });

                        rd.close();
                    } else if (retCode == 404) {
                        tryAgain = false;
                        rd = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "UTF-8"));
                        while ((line = rd.readLine()) != null) {
                            result += line;
                        }
                        rd.close();
                    } else {
                        tryAgain = true;
                        rd = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "UTF-8"));
                        while ((line = rd.readLine()) != null) {
                            result += line;
                        }
                        rd.close();
                        logger.debug(new Date() + " GET " + resource + " RETURNED " + retCode + ":" + ret);
                        logger.debug(new Date() + " ERRORSTREAM = " + result);
                    }
                } catch (SocketTimeoutException e) {
                    tryAgain = true;
                    logger.debug(new Date() + " GET " + resource + " " + e.getLocalizedMessage());
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("error with API processing", e);
        }
        return response;
    }


    public static void eventsAPI(String startDate, String endDate) throws UnsupportedEncodingException{

        String[] ret = get(tenantUrl +
                "/events?filter=published%20gt%20%22" + URLEncoder.encode(startDate, "UTF-8") +
                "%22%20and%20published%20lt%20%22" + URLEncoder.encode(endDate, "UTF-8") +
                "%22%20and%20%28action.objectType%20eq%20%22core.user_auth.login_success%22%20or%20" +
                "action.objectType%20eq%20%22core.user_auth.idp.saml.login_success%22%20or%20action.objectType%20eq%20" +"" +
                "%22core.user_auth.idp.saml.login_success%22+or+action.objectType+eq+%22app.ldap.login.success%22+or+action.objectType+eq+%22app.ad.login.success%22%29", token);
        while(!ret[0].equals("[]")) {
            getUniqueUsersFromEvent(ret[0]);
            if(ret[1] != null && !ret[1].trim().equals("")) {
                ret = get(ret[1], token);
            }
        }
        UniqueUsers.getCSV(tenantUrl);
        UniqueUsers.getRawCSV(tenantUrl);
    }

    public static void getUniqueUsersFromEvent(String ret) {

        //Check to make sure there is a login
        JSONArray eventAftArr = new JSONArray(ret);

        for (int i = 0; i < eventAftArr.length(); i++) {

            if (eventAftArr.getJSONObject(i).getJSONObject("action").getString("objectType").equals("core.user_auth.login_success")) {
                try {
                    String login = eventAftArr.getJSONObject(i).getJSONArray("targets").getJSONObject(0).getString("login");
                    String requestId = eventAftArr.getJSONObject(i).getString("requestId");
                    String published = eventAftArr.getJSONObject(i).getString("published");
                    try {
                        UniqueUsers.addUser(login, formatter.parse(published.replaceAll("Z$", "+0000")), requestId);
                    } catch (java.text.ParseException pe) {
                        logger.error("Date Parse issue for " + login + " date: " + published, pe);
                        System.exit(-1);
                    }
                } catch (JSONException je) {
                    logger.debug(je);
                    logger.debug(eventAftArr.getJSONObject(i).toString());
                }
            } else {
                if (!eventAftArr.getJSONObject(i).getJSONArray("targets").getJSONObject(0).isNull("login")) {
                    String login = eventAftArr.getJSONObject(i).getJSONArray("targets").getJSONObject(0).getString("login");
                    String idpSource = eventAftArr.getJSONObject(i).getJSONArray("targets").getJSONObject(1).getString("displayName");
                    String requestId = eventAftArr.getJSONObject(i).getString("requestId");
                    UniqueUsers.addIdpSource(login, requestId, idpSource);
                }
            }
        }
        return;
    }


    public static void main(String[] args) throws Exception {

        logger.info("Entering Application...");

        // create the command line parser
        CommandLineParser parser = new DefaultParser();

        // create the Options
        Options options = new Options();

        options.addOption(Option.builder().longOpt("oktaorg")
                                        .hasArg()
                                        .required()
                                        .desc("enter your okta org i.e. https://youroktaorg.okta.com")
                                        .build());
        options.addOption(Option.builder().longOpt("apikey")
                .hasArg()
                .desc("enter your apikey if not present you will be asked when program starts")
                .build());
        options.addOption(Option.builder().longOpt("startDate")
                .hasArg()
                .required()
                .desc("start date in the following format YYYY-MM-DDTHH:MM:SS.sssZ")
                .build());
        options.addOption(Option.builder().longOpt("endDate")
                .hasArg()
                .required()
                .desc("end date in the following format YYYY-MM-DDTHH:MM:SS.sssZ")
                .build());

        boolean displayApiKeyEnterMsg = true;
        String startEntered = "";
        String endEntered = "";

        try {
            // parse the command line arguments
            CommandLine line = parser.parse( options, args );

            // validate that block-size has been set
            if( line.hasOption( "apikey" ) ) {
                displayApiKeyEnterMsg = false;
            }
            Console console = System.console();
            //tenantUrl = console.readLine("Enter BCBSA Okta org url:");
            tenantUrl = line.getOptionValue("oktaorg");
            tenantUrl = tenantUrl + "/api/v1";
            if(displayApiKeyEnterMsg) {
                token = console.readLine("Enter API Token:");
            } else {
                token = line.getOptionValue("apikey");
            }
            startEntered = line.getOptionValue("startDate");
            endEntered = line.getOptionValue("endDate");
            //startEntered = console.readLine("Enter Report Start Date in this format :YYYY-MM-DDT00:00:00.000Z:");
            //endEntered = console.readLine("Enter Report End Date in this format :YYYY-MM-DDT00:00:00.000Z:");
            eventsAPI(startEntered, endEntered);
        }
        catch( ParseException exp ) {
            System.out.println(exp.getMessage());
            logger.error( exp.getMessage() );
            System.exit(-1);
        }
    }
}
