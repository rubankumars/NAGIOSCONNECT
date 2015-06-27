package com.plugins.nagios;

import hudson.Launcher;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.AbstractProject;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;

import javax.servlet.ServletException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;	
import java.text.ParseException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.net.UnknownHostException;
import java.net.MalformedURLException;
import java.lang.NullPointerException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.text.SimpleDateFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Date;
import java.util.Calendar;

/**
 *
 * @author Rubankumar
 * @Email ruban.yuvaraj@gmail.com
 *
 */

public class NagiosConnect extends Builder {

    private final String servername;
    private final String jobname;
    int minutes = 0;
    private final String nagiosStatus;
    static HttpURLConnection connection = null; 

    //Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
    @DataBoundConstructor
    public NagiosConnect(String servername, String jobname, int minutes, String nagiosStatus) {
        this.servername = servername;
	this.jobname = jobname;
	this.minutes = minutes;
	this.nagiosStatus = nagiosStatus;
    }

    /**
     * We'll use this from the <tt>config.jelly</tt>.
     */
    public String getServername() {
        return servername;
    }
    public String getJobname() {
        return jobname;
    }
    public int getMinutes() {
        return minutes;
    }
    public String getNagiosStatus(){
	return nagiosStatus;
    }

	//Create all-trusting trust manager
	static TrustManager[] trstcrt = new TrustManager[] {new X509TrustManager() {
       		 public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            		return null;
       		 }	
         	 public void checkClientTrusted(X509Certificate[] certs, String authType) {
        	 }
        	 public void checkServerTrusted(X509Certificate[] certs, String authType) {
        	 }
    	 }
	};

	public static void sslIgnore() throws KeyManagementException, NoSuchAlgorithmException{
        //Install the all-trusting trust manager
        SSLContext sc;
		try {
			sc = SSLContext.getInstance("SSL");
			sc.init(null, trstcrt, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		} catch (NoSuchAlgorithmException e) {
			throw e;
	 	}catch (KeyManagementException e) {
			throw e;
		}

        //Create all-trusting host name verifier
        HostnameVerifier validAllHosts = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        //Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(validAllHosts);
	}

	//Authenticates Nagios application and create a connection
	public static HttpURLConnection nagiosAuth(String NAGIOSURL,String user, String password) throws MalformedURLException, IOException{
                        final String username = user;
                        final String pass = password;
		        URL url = null;
			try {
				url = new URL(NAGIOSURL);
			}catch (MalformedURLException e) {
				throw e;
			}
                        Authenticator.setDefault (new Authenticator() {
                                protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication (username, pass.toCharArray());
                                }
                        });
			try{
                        connection = (HttpURLConnection)url.openConnection();
			}catch(IOException e){
				throw e;
			}
			return connection;
	}

	public static String excutePost(String NAGIOSURL, String URLPARAMETER, String user, String password, boolean sslCheck) throws Exception{
				final String username = user;
			final String pass = password;
			final boolean ssl = sslCheck;
		  try {
			
			if (ssl)
				//Calling sslIgnore method to bypass ssl hand shake
				sslIgnore();  
			
			connection = nagiosAuth(NAGIOSURL,username,pass);
		    	connection.setRequestMethod("POST");

			// setting the request property to ensure a robust data transfer
		    	connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		    	connection.setRequestProperty("Content-Length",Integer.toString(URLPARAMETER.getBytes().length));
		    	connection.setRequestProperty("Content-Language", "en-US"); 

		    	connection.setUseCaches(false); // Some protocols do caching of documents. Occasionally, it is important to be able to "tunnel through" and ignore the caches (e.g., the "reload" button in a browser). If the UseCaches flag on a connection is true, the connection is allowed to use whatever caches it can. If false, caches are to be ignored. The default value comes from DefaultUseCaches, which defaults to true.

		    	connection.setDoOutput(true);  // A URL connection can be used for input and/or output. Set the DoOutput flag to true if you intend to use the URL connection for output, false if not. The default is false.

		    	//Send request
		    	DataOutputStream wr = new DataOutputStream (
		        connection.getOutputStream());
		    	wr.writeBytes(URLPARAMETER);
		    	wr.close();

		    	//Get Response  
		    	InputStream is = connection.getInputStream();
		    	BufferedReader rd = new BufferedReader(new InputStreamReader(is));
		  	StringBuffer response = new StringBuffer();
		    	String line;
		    	while((line = rd.readLine()) != null) {
		      		response.append(line);
		      		response.append('\r');
		      	}
		    	rd.close();
		    	return response.toString();
		  	} catch (Exception e) {
				throw e;
		  	} finally {
		    		if(connection != null) {
		      		connection.disconnect(); 
		    	}
		  	}
		}

    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener) {
        
	    listener.getLogger().println("ServerName you have entered is " + servername);
            listener.getLogger().println("JobName you have entered is " + jobname);
            listener.getLogger().println("Minutes you have entered is " + minutes);
            listener.getLogger().println("Service entered is " + nagiosStatus);
	    
	    //Assining the global form values to a local variables
            final String url = getDescriptor().getNagiosUrl();
            final String user = getDescriptor().getNagiosUser();
            final String password = getDescriptor().getNagiosPassword();
	    final String NAGIOSURL = url + "/cgi-bin/cmd.cgi";
	    final boolean sslCheck = getDescriptor().getSslCheck();
	    
            //Fetch current system date and time, advance it by so and so minutes as given by user 
	    String pattern =  "MM-dd-yyy HH:mm:ss";
	    SimpleDateFormat format = new SimpleDateFormat(pattern);
	    Date now = new Date();
	    String startDate = format.format(now);
		Date advanceTime = null;
		try{
			advanceTime = format.parse(startDate);
		}catch (ParseException e) {
                        StringWriter errors =  new StringWriter();
                        e.printStackTrace(new PrintWriter(errors));
			listener.getLogger().println(errors.toString());
		} 
	    Calendar cal = Calendar.getInstance();
	    cal.setTime(advanceTime);
	    cal.add(Calendar.MINUTE, minutes);
	    String endDate =  format.format(cal.getTime());

            listener.getLogger().println("StartDate " + startDate);
            listener.getLogger().println("EndDate " + endDate);
	    
	    String successMsg = "Your command request was successfully submitted to Nagios for processing";
	    String errorMsg = "We got the below error message from NAGIOS, please check your configuration...";
	    String comment = "Paused by Jenkins";

	    //nagiosPause condition will be executed if the user choose the Pause service in the form 
		if(nagiosStatus.equals("nagiosPause")){

                	String URLPARAMETER = "cmd_typ=56&cmd_mod=2&host="+servername+"&service="+jobname+"&com_data="+comment								+"&trigger=0&start_time="+startDate+"&end_time="+endDate+"&fixed=1&hours=2&minutes=0&btnSubmit=Commit";
			String data = null;
			try{
                		data = excutePost(NAGIOSURL,URLPARAMETER,user,password,sslCheck);
		 		
				if (data.contains(successMsg)){
        	 			listener.getLogger().println(minutes+" min(s) downtime has been scheduled for the service '"+jobname							+"' on server '"+servername+"'");
         			}else if (data.contains("errorMessage")){
					listener.getLogger().println(errorMsg);
        	 			for(int index = data.indexOf("errorMessage");index>=0; index = data.indexOf("errorMessage", index+1))
             				{
                     				String error = data.substring(index+14, index+80);
                     				listener.getLogger().println(error);
             				}
				 }
			}catch(Exception e){
				listener.getLogger().println(e.getMessage());
			}
		}

	     //nagiosStart condition will be executed if the user choose the Start service in the form
		else if (nagiosStatus.equals("nagiosStart")){
			final String NAGIOSURL_DOWNID = url + "/cgi-bin/extinfo.cgi";
			String URLPARAMETER = "type=6";
			try{
			String output=excutePost(NAGIOSURL_DOWNID,URLPARAMETER,user,password,sslCheck);
			for(int index = output.indexOf("down_id");index>=0; index = output.indexOf("down_id", index+1))
			{
				String a = output.substring(index-500, index+15);
				if ( (a.indexOf(servername)>-1) && (a.indexOf(jobname)>-1) ){
				String b = output.substring(index, index+20);
				String downtime_ID =  (b.substring(8, b.indexOf("'><"))).trim();
				String URLPARAMETER_DEL = "cmd_mod=2&cmd_typ=79&down_id="+downtime_ID+"btnSubmit=Commit";
				String data = excutePost(NAGIOSURL,URLPARAMETER_DEL,user,password,sslCheck);		
			
                                if (data.contains(successMsg)){
                                        listener.getLogger().println("Downtime ID - " + downtime_ID+ " with reference to the service '"+jobname							+"' and the server '"+servername+"' is enabled for notification");
                                }else if (data.contains("errorMessage")){
                                        for(int erridx = data.indexOf("errorMessage");erridx>=0; index = data.indexOf("errorMessage", erridx+1))
                                        {
                                                listener.getLogger().println(errorMsg + "\n");
                                                String error = data.substring(erridx+14, erridx+80);
                                                listener.getLogger().println(error);
                                        }

                                      }
				}
			}
			}catch(Exception e){
                               listener.getLogger().println(e.getMessage());
                        }
	       }
	return true;
    }

	//IsMatch method will be called by FormValidation to validate the URL entered against a generic URL pattern 
	private static boolean IsMatch(String s, String pattern) {
        	try {
            		Pattern patt = Pattern.compile(pattern);
            		Matcher matcher = patt.matcher(s);
	                return matcher.matches();
	        } catch (RuntimeException e) {
//		        return false;
			throw e;
	    	}       
	}
	
    // Overridden for better type safety.
    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }

    /**
     * Descriptor for {@link NagiosConnect}. Used as a singleton.
     * The class is marked as public so that it can be accessed from views.
     */
    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        /**
         * To persist global configuration information,
         * simply store it in a field and call save().
         *
         * <p>
         * If you don't want fields to be persisted, use <tt>transient</tt>.
         */
        private String nagiosUrl;
        private String nagiosUser;
        private String nagiosPassword;
	private boolean sslCheck;

        /**
         * Performs on-the-fly validation of the form fields.
         *
         * @param nagiosUrl
         *      This parameter receives the value that the user has typed.
         * @return
         *      Indicates the outcome of the validation. This is sent to the browser.
         */
        public FormValidation doCheckNagiosUrl(@QueryParameter String nagiosUrl, @QueryParameter String nagiosUser, 						@QueryParameter String nagiosPassword, @QueryParameter boolean sslCheck) throws Exception, IOException, ServletException {	
	String URL_PATTERN = "^(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
	String syntax = "Syntax should be http://nagios_hostname/nagios (or) https://nagios_hostname/nagios";
		if (nagiosUrl.length() == 0)
                        return FormValidation.error("Enter the Nagios URL");

		if(sslCheck)
			sslIgnore();

                try{
                    connection = nagiosAuth(nagiosUrl,nagiosUser,nagiosPassword);
                         if(!(connection.getResponseMessage().equals("OK")))
                                        return FormValidation.error(connection.getResponseMessage());                             
                         if(!(IsMatch(nagiosUrl,URL_PATTERN)))
                        		return FormValidation.error(syntax);

                   }catch(UnknownHostException e){
                                        return FormValidation.error("UnknownHostException: unable to find the host - " + e.getMessage());
		   }catch(NullPointerException ex1){
                                        return FormValidation.error(ex1.getMessage());
                   }catch(MalformedURLException ex2){
                                        return FormValidation.error("Malformed URL: " + ex2.getMessage()+ "\n"+syntax);
		   }catch(Exception ex3){
                                        return FormValidation.error(ex3.getMessage());
		   }
        return FormValidation.ok();
	}
	
	public FormValidation doCheckServername(@QueryParameter String nagiosUrl, @QueryParameter String nagiosUser,                                                     @QueryParameter String nagiosPassword, @QueryParameter boolean sslCheck, @QueryParameter String servername) 						throws IOException, ServletException {
	
	    public static String Nurl = getDescriptor().getNagiosUrl();
            //final String user = getDescriptor().getNagiosUser();
            //final String password = getDescriptor().getNagiosPassword();
	
	String url = nagiosUrl + "/cgi-bin/status.cgi";
	String param = "host=all";
	boolean status;
		if (servername.length() == 0)
                        return FormValidation.error("Enter the Servername");

		try{
		String data = excutePost(url,param,nagiosUser,nagiosPassword,sslCheck);
		status = data.contains(servername);
                if(!(status))
                        return FormValidation.error("Unable to find " +servername);
		}catch(Exception ex){
			return FormValidation.error(ex.getMessage());
		}
	return FormValidation.ok();
	}

        public FormValidation doCheckJobname(@QueryParameter String nagiosUrl, @QueryParameter String nagiosUser,                                                     @QueryParameter String nagiosPassword, @QueryParameter boolean sslCheck, @QueryParameter String jobname)                                            throws IOException, ServletException {

        String url = nagiosUrl + "/cgi-bin/status.cgi";
        String param = "host=all";
	boolean status;
                if (jobname.length() == 0)
                        return FormValidation.error("Enter the Job/Service name");
                try{
                String data = excutePost(url,param,nagiosUser,nagiosPassword,sslCheck);
		status = data.contains(jobname);
                if(!(status))
                        return FormValidation.error("Unable to find " +jobname+"\n"+data);
		}catch(Exception ex){
                        return FormValidation.error(ex.getMessage());
		}
        return FormValidation.ok();
        }


        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            // Indicates that this builder can be used with all kinds of project types 
            return true;
        }

        /**

         * This human readable name is used in the configuration screen.
         */
        public String getDisplayName() {
            return "Nagios Configuration";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            // To persist global configuration information,
            // set that to properties and call save().
            nagiosUrl = formData.getString("nagiosUrl");
	    nagiosUser = formData.getString("nagiosUser");
	    nagiosPassword = formData.getString("nagiosPassword");
	    sslCheck =  formData.getBoolean("sslCheck");
            // Can also use req.bindJSON(this, formData);
            // (easier when there are many fields; need set* methods for this)
            save();
            return super.configure(req,formData);
        }

        /**
         * This method returns the global configuration values set for NAGIOS configuration
         */
       public String getNagiosUrl() {
         return nagiosUrl;
       }

       public String getNagiosUser() {
         return nagiosUser;
       }

       public String getNagiosPassword() {
         return nagiosPassword;
       }

       public boolean getSslCheck() {
         return sslCheck;
       }

    }
}

