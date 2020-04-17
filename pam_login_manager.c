#include<stdio.h>
#include<security/pam_appl.h>
#include<security/pam_misc.h>
#include<pwd.h>
#include<stdlib.h>
#include<sys/types.h>
#include<unistd.h>
#include<stdbool.h>
#include<string.h>
static pam_handle_t *pamh;
static int ret_val;
static struct pam_conv pam_communication = {misc_conv,NULL};

void pam_stop(int result){
 	result = pam_end(pamh,result);
	if(result == PAM_SUCCESS){
		printf("Pam is Closed\n");
	}
	exit(0);
}

void print_error(char *message){
	printf("Error : %s : %s \n",message,pam_strerror(pamh,ret_val));
	pam_stop(0);
}

void logout(){
	ret_val = pam_close_session(pamh, ret_val);
    	if (ret_val != PAM_SUCCESS) {
        	pam_setcred(pamh, PAM_DELETE_CRED);
        	print_error("pam_close_session");
   	}else{
		printf("Session Closed\n");
	}
    
   	ret_val = pam_setcred(pamh, PAM_DELETE_CRED);
   	if (ret_val != PAM_SUCCESS) {
        	print_error("pam_setcred");
    	}else{
		printf("User Credentials Deleted\n");
	}
	pam_stop(ret_val);
}
void login(char *service_name,char *user){
	
	ret_val = pam_start(service_name,user,&pam_communication,&pamh);
	
	if(ret_val != PAM_SUCCESS){
		print_error("pam_start_error");
		exit(1);
	}else{
		printf("Module Started Sucessfully\n");
	}
	ret_val = pam_authenticate(pamh,ret_val);
	if(ret_val == PAM_USER_UNKNOWN ){
		print_error("Unknown User");		
		exit(1);
	}else if(ret_val != PAM_SUCCESS ){	
		print_error("Not Authorized");
		exit(1);
	}else{
		printf("Authentication Sucessfull\n");
	}	
	ret_val = pam_acct_mgmt(pamh, ret_val);
	if(ret_val != PAM_SUCCESS ){
		print_error("No Access To Account");
		exit(1);
	}else{
		printf(" Access Granted \n");
	}

	ret_val = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    	if (ret_val != PAM_SUCCESS) {
		print_error("Not Able To Set Credentials");
	}else{
		printf("User Credential is Setup\n");
	}

    	ret_val = pam_open_session(pamh, ret_val);
    	if (ret_val != PAM_SUCCESS) {
        	pam_setcred(pamh, PAM_DELETE_CRED);
		print_error("No Session is setup");
    	}else{
		printf("Session Is Open For User \n");
	}
	
	//return ret_val;
}

void set_env(char *name,char *value){
	
	size_t name_value_len = strlen(name) + strlen(value) + 2;
    	char *name_value = malloc(name_value_len);
    	snprintf(name_value, name_value_len,  "%s=%s", name, value);
    	pam_putenv(pamh, name_value);
    	free(name_value);
}

void init_env(struct passwd *pw){
   	
	set_env("TERM","xterm");
   	set_env("HOME", pw->pw_dir);
    	set_env("PWD", pw->pw_dir);
    	set_env("SHELL", pw->pw_shell);
    	set_env("USER", pw->pw_name);
    	set_env("LOGNAME", pw->pw_name);
    	set_env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/bin");
    		
	size_t mail_dir_len = strlen(pw->pw_name) + strlen("/var/spool/mail/");
	char *mail_dir = malloc(mail_dir_len);
	snprintf(mail_dir,mail_dir_len, "/var/spool/mail/%s", pw->pw_name);
	set_env("MAIL",mail_dir);

    	size_t xauthority_len = strlen(pw->pw_dir) + strlen("/.Xauthority") + 1;
    	char *xauthority = malloc(xauthority_len);
    	snprintf(xauthority, xauthority_len, "%s/.Xauthority", pw->pw_dir);
    	set_env("XAUTHORITY", xauthority);
    	free(xauthority);
}


int main(int argc,char **argv){

	char *service_name ="system-login";
	char *user= malloc(2*sizeof(char));
	printf("Username : ");
	scanf("%s",user);
	struct passwd *pwd = getpwnam(user);
	login(service_name,pwd->pw_name);
	init_env(pwd);
	logout();	
}
