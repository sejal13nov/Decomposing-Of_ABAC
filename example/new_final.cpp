#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include<string.h>
#include <sstream>
using namespace std;
string DecisionTable[1000][100];
string DACtable[100][100];
int dac2[100][100];
string Attributetable[100][100];
string arraycheck[100];
string input1[100];
string input2[100];
string RbacUserRole[100][100];
string RbacRoleActivity[100][100];
int Rbac_roles=0;
int Rbac_act_cols=0;   ///euals to no. of objects;
int total_input=0;     /// query 
int RulesFromData;
int Decision_rows=0;    // can get from metadata
int Users=0;           //from metadata subjects

int actions=0;         //from metadata 
int DAC_rows=0;        // no. of users
int Decision_cols=0;
int no_of_Rules=0;
int no_of_Attri_con=0; // no. of lines in data rules
int total_users,total_objects;

///////////// used in Create DAC
int user=0, obj=0,total_actions=0;

//////used in MAC
int secret;
int topsecret;
int confidential;
int unclassified;
int cont_row_in_dac,cont_col_in_dac;  //used while check
int user_level,object_level;  //used for MAC
string current_user,current_obj,current_activity,current_role;  //from query
void intial_mac()
{
 unclassified =1;
 secret = 2;
 topsecret =3;
 confidential =4; 
}
void generate_dac2()
{
	int c=0;;
	for(int i=0;i<total_users;i++)
		for(int j=0;j<total_objects;j++)
			{
			dac2[i][j]=c++;
			//cout<<c;
			}

}

void printdac2()
{
	for(int i=0;i<total_users;i++)
	{
		for(int j=0;j<total_objects;j++)
			{
               		cout<<dac2[i][j]<<" ";
                   
                 	}
		cout<<endl;
	}
}
void get_inputQuery(char * file)
{
	ifstream inFile;
	std::string line;
	int total_para;
	inFile.open(file);
    	if (!inFile) {cout << "Unable to open file metadata"; }
	while (getline(inFile, line))
	{
  
		string Words[100];
        
		short counter = 0;
		for (short i = 0; i<line.length(); i++)
          	 {
			if (line[i] == ' ')
        			{counter++;}
			else
        			{Words[counter] += line[i];}
        	
            	} 
	
		input1[total_input]=Words[0];
        	input2[total_input++]=Words[1];
          	    
	}
}
void print_Query()
{
	for(int i=0;i<total_input;i++)
	{
	cout<<input1[i]<<"  "<<input2[i]<<"  ";
	}
}
void get_metadata(char* file)
{
	ifstream inFile;
	std::string line;
	int total_para;
	int dec_row=0;
	inFile.open(file);
	if (!inFile) {cout << "Unable to open file metadata"; }
	while (getline(inFile, line))
	{
  
		string Words[100];
        
		short counter = 0;
		for (short i = 0; i<line.length(); i++)
          	 {
			if (line[i] == ' ')
        			{counter++;}
			else
        			{Words[counter] += line[i];}
        
            	} 
		total_para = counter+1  ;
		for(int j=1;j<total_para;j++)
		{
		 	DecisionTable[dec_row][0]=Words[0];
                 	DecisionTable[dec_row++][1]=Words[j];
          	}
    
     
	}
	Decision_rows=dec_row++;
}
void get_policy(char * file)
{
	int temp=0;
	ifstream inFile;
	std::string line;
	int total_para;
	inFile.open(file);
	if (!inFile) {cout << "Unable to open file 2"; }
	while (getline(inFile, line))
	{
	//cout<<line<<endl;
	string Wordsdata[100];
        
	short counter = 0;
	for (short i = 0; i<line.length(); i++)
             {
           
		if (line[i] == ' ')
        		{counter++;}
		else
        		{Wordsdata[counter] += line[i];}
        
                 } 
	total_para = counter+1  ;
	for(int j=0;j<total_para;j++)
		{
                  //cout<<Wordsdata[j]<<" ";
		for(int k=0;k<Decision_rows;k++)
                 {
                         if(Wordsdata[j].compare(DecisionTable[k][1]) == 0)
                               {  //cout<<"found";
                                  DecisionTable[k][temp+2] = "T";
                                }
                  }
                for(int k=0;k<Decision_rows;k++)
                       {
                        if(DecisionTable[k][temp+2].compare("T") != 0)
                               {  //cout<<"found";
                                  DecisionTable[k][temp+2] = "F";
                                }
                       }
          	}
          temp++;
	}
	Decision_cols=temp+2;
	no_of_Rules=temp;

}
void print_initial_DecisionTable()
{
	for(int i=0;i<Decision_rows;i++)
	{
		cout<<DecisionTable[i][0]<<" "<<DecisionTable[i][1]<<endl;
	}
}
void print_initial_DecisionTable_tofile()
{
	ofstream outdata;  
	outdata.open("InialDecisiontable"); // opens the file
	if( !outdata ) 
		{
      		cerr << "Error: file could not be opened" << endl;
               }
	for(int i=0;i<Decision_rows;i++)
	{
		outdata<<DecisionTable[i][0]<<" "<<DecisionTable[i][1]<<endl;
	}
}
void print_final_DecisionTable_tofile()
{
	ofstream outdata;  
	outdata.open("FinalDecisiontable"); // opens the file
	if( !outdata ) 
		{
      		cerr << "Error: file could not be opened" << endl;
               }
	for(int i=0;i<Decision_rows;i++)
         	{
         	  for(int j=0;j<Decision_cols;j++)
                           outdata<<DecisionTable[i][j]<<" ";
                outdata <<endl;
                } 
}
void print_array_tobe_checked()
{
	//for(int j=0;j<total_users*total_objects;j++)
	for(int i=0;i<no_of_Attri_con;i++)
			{
			cout<<arraycheck[i]<<endl;
			}
}
void print_attribute_constraint()
{
	//cout<<"here";
	ofstream outdata; 
	//cout<<att[0][0]; 
	outdata.open("AttributeConstraints"); // opens the file
	if( !outdata ) {
		cerr << "Error: file could not be opened" << endl;
               }
	for(int i=0;i<no_of_Attri_con;i++)
	{
    	//cout<<"hiiii   ";
    		for(int j=0;Attributetable[i][j].compare("")!=0;j++)
       			{
			//cout<<att[i][j]<<"";
         			outdata<<Attributetable[i][j]<<" ";
       			}
     		outdata<<endl;
	}
}

void create_map(string act,int attri, int rows,int cols)
{
	int n=dac2[rows-1][cols-1];
	arraycheck[n].append(act);
	ostringstream str1;
	str1 << attri;
	string temp = str1.str();
	arraycheck[n].append(temp);
	arraycheck[n].append(",");
}
void add_att(string a, string b, string c, int d,int row,int col)
{
	string attWords[100];
	int att_count=0;
	int dec_rules=d+2;
	for(int i=0;i<Decision_rows;i++)
		{
			if(DecisionTable[i][dec_rules].compare("T") == 0 && DecisionTable[i][0].compare("Subject")!=0 && DecisionTable[i][0].compare("Objects")!=0 && DecisionTable[i][0].compare("Action")!=0 && DecisionTable[i][0].compare("Clearance")!=0 && DecisionTable[i][0].compare("Classification")!=0)
				{
	 			attWords[att_count++]=DecisionTable[i][0];
	 			attWords[att_count++]=DecisionTable[i][1];
        
				}
		}
	for(int i=0;i<att_count;i++)
  	{
		Attributetable[no_of_Attri_con][i]=attWords[i]; 
          
  	 }
	create_map(c,no_of_Attri_con,row,col);
	no_of_Attri_con++;

}
void add_DAC_activity(string a, string b, string c, int d)
{
	int row,col;
	int dec_rules=d+2;
	int flag = 0;
	for(int i=0;i<=user;i++)
	{
		for(int j=0;j<=obj;j++)
		{
			//cout<<dac[i][0]<<endl;
			if(DACtable[i][0].compare(a)==0 && DACtable[0][j].compare(b)==0) 
				{
                       			if(DACtable[i][j].compare("")==0)
                             			{
						DACtable[i][j].append(c);
						DACtable[i][j].append(",");
						//dac2[i][j]=attribute_table_count;
                             			}
                         		else
                            			{
                            			 std::size_t found = DACtable[i][j].find(c);
                              			 if (found!=std::string::npos)
                                    			{
                                    			// cout<<"found";
				        		flag=1;
							//dac2[i][j]=attribute_table_count;
                                   		 	}
                              			else
                                  			{
                                   			DACtable[i][j].append(c);
				   			DACtable[i][j].append(",");
                                  			}
                            	}
                        
                       	row=i;
			col=j;
			
		}
	}
} 
	add_att(a,b,c,d,row,col);


}
void create_DACtable()
{

	string user_role,user_object,user_action;
	for(int i=0;i<Decision_rows;i++)
	{
		if(DecisionTable[i][0].compare("Subject")==0) 
		{
			user++; //total_users;
			DACtable[user][0]=DecisionTable[i][1];
		}
		   
         if(DecisionTable[i][0].compare("Objects")==0) 
		{
			obj++;
			DACtable[0][obj]=DecisionTable[i][1];
		} 
         if(DecisionTable[i][0].compare("Action")==0) 
		{
			total_actions++;
			
		}   
             
      }

	for(int i=2;i<Decision_cols;i++)
	     {
		for(int j=0;j<Decision_rows;j++)
             	{
			if(DecisionTable[j][i].compare("T")==0)
                       		{
				if(DecisionTable[j][0].compare("Subject")==0)
                                	{
                                 	user_role=DecisionTable[j][1];
                              		 }
				if(DecisionTable[j][0].compare("Objects")==0)
                                	{
                                	 user_object=DecisionTable[j][1];
                                	}
                       		 if(DecisionTable[j][0].compare("Action")==0)
                                	{
                                 	user_action=DecisionTable[j][1];
                                	}
				}
		}
      add_DAC_activity(user_role,user_object,user_action,i-2);
      //cout<<"dac"<<user_role<<"**"<<user_object<<"**"<<user_action<<endl;
     }
}
void print_DACtable()
{
	ofstream outdata;  
	outdata.open("DAC"); // opens the file
	if( !outdata ) {
      		cerr << "Error: file could not be opened" << endl;
               	}


	for(int i=0;i<=user;i++)
         {
           for(int j=0;j<=obj;j++)
               {  if(DACtable[i][j]=="")
                      outdata <<"***";
                 outdata <<DACtable[i][j]<<" "; }
           outdata <<endl;
         } 
}
void get_users()
{
	int r=0;
	for(int i=0;i<Decision_rows;i++)
      	{
         if(DecisionTable[i][0].compare("Subject")==0) 
		r++;       
             
      	}
total_users=r;
}
int get_objects()
{
	int o=0;
	for(int i=0;i<Decision_rows;i++)
		if(DecisionTable[i][0].compare("Objects")==0) 
			o++;
			
	
total_objects=o;
}
void get_rbac_user(char * file)
{
int rbac_roles=0;
	ifstream inFile;
	std::string line;
	int total_para;
	inFile.open(file);
	//int i=0;
	//int temp=0;
	if (!inFile) {cout << "Unable to open file metadata"; }
	while (getline(inFile, line))
	{
  		string Words[100];
       
		short counter = 0;
		for (short i = 0; i<line.length(); i++)
          	{
			if (line[i] == ' ')
        			{counter++;}
			else
        			{Words[counter] += line[i];}
       
            	} 
	
		RbacRoleActivity[rbac_roles+1][0]=Words[0];
        	total_para = counter+1  ;
		for(int j=0;j<total_para;j++)
			{
			//rbac[rbac_roles][0]=Words[0];
		 	RbacUserRole[rbac_roles][j]=Words[j];
                 
         		}
         	rbac_roles++;
	}
	Rbac_roles=rbac_roles++;                  	    
}
void print_RbacUser()
{
	ofstream outdata;  
	outdata.open("RbacUser"); // opens the file
	if( !outdata ) {
      		cerr << "Error: file could not be opened" << endl;
               	}


	for(int i=0;i<Rbac_roles;i++)
         	{
           	for(int j=0;RbacUserRole[i][j].compare("")!=0;j++)
                 	outdata<< RbacUserRole[i][j]<<" ";
           	outdata <<endl;
         	} 
}
void add_rbac(string a, string b, string c)
{
//cout<<a<<b<<c;
	for(int i=1;i<=Rbac_roles;i++)
	{
		for(int j=1;j<=Rbac_act_cols;j++)
		{
			if(RbacRoleActivity[i][0].compare(a)==0 && RbacRoleActivity[0][j].compare(b)==0) 
				{
                       			 if(RbacRoleActivity[i][j].compare("")==0)
                            		 	{
                              		 	// cout<<a<<" "<<b<<" "<<c<<" "<<"add";
				
						RbacRoleActivity[i][j].append(c);
						RbacRoleActivity[i][j].append(",");
						//dac2[i][j]=attribute_table_count;
                             			}
                        		 else
                           			 {
                             			std::size_t found = RbacRoleActivity[i][j].find(c);
                             			 if (found!=std::string::npos)
                                    			{
                                    			// cout<<"found";
				     			 //  flag=1;
							//dac2[i][j]=attribute_table_count;
                                    			}
                              			else
                                 		 	{
                                   			RbacRoleActivity[i][j].append(c);
				 			RbacRoleActivity[i][j].append(",");
                                 			 }
                            			}
                        
                       
				}
		}
	} 
}


void get_RbacAct(char * file)
{
	
	Rbac_act_cols++;
	for(int i=0;i<Decision_rows;i++)
	{
     		if(DecisionTable[i][0].compare("Objects")==0)
			{
          		// rbac_act[0][rbac_act_cols++]="sejal";
	  		 RbacRoleActivity[0][Rbac_act_cols++]=DecisionTable[i][1];
	  		// cout<<rbac_act[0][rbac_act_cols-1];
			}
	}
	//cout<<rbac_act_cols;
	//cout<<rbac_roles;
	ifstream inFile;
	std::string line;
	int total_para;
	inFile.open(file);
	//int i=0;
	//int temp=0;
	if (!inFile) {cout << "Unable to open file metadata"; }
	while (getline(inFile, line))
	{
  		string Words[100];
       
		short counter = 0;
		for (short i = 0; i<line.length(); i++)
          	{
			if (line[i] == ' ')
        			{counter++;}
			else
        			{Words[counter] += line[i];}
       
            	} 
	
	
        	//temp = counter+1  ;
		add_rbac(Words[0],Words[1],Words[2]);
	
	}


}
void print_RbacAct()
{
	ofstream outdata;  
	outdata.open("rbac1"); // opens the file
	if( !outdata ) {
      			cerr << "Error: file could not be opened" << endl;
               		}


	for(int i=0;i<=Rbac_roles;i++)
         	{
           		for(int j=0;j<Rbac_act_cols;j++)
               		{  
				if(RbacRoleActivity[i][j]=="")
                      			outdata <<"***";
                 		outdata <<RbacRoleActivity[i][j]<<" "; 
               		 }
         		outdata <<endl;
         	}
}
void initialize()
{

	
}
int check_mac()
{
	int flag=0;
	for(int i=0;i<total_input;i++)
	{
    		if(input1[i].compare("Clearance")==0)
			{
		 	 	if(input2[i].compare("secret")==0)
					user_level=secret;
		 		else if (input2[i].compare("topsecret")==0)
					user_level=topsecret;
	 			else if (input2[i].compare("confidential")==0)
					user_level=confidential;
	 			else if (input2[i].compare("unclassified")==0)
					user_level=unclassified;
			}
		if(input1[i].compare("classification")==0)
			{
 				if(input2[i].compare("secret")==0)
					object_level=secret;
 				else if (input2[i].compare("topsecret")==0)
					object_level=topsecret;
 				else if (input2[i].compare("confidential")==0)
					object_level=confidential;
 				else if (input2[i].compare("unclassified")==0)
					object_level=unclassified;
	      		}
	}
	for(int i=0;i<total_input;i++)
	{

		if(input1[i].compare("Action")==0)
			{
				if(input2[i].compare("read")==0)
					{
         				flag=1;
	 					if(user_level>=object_level)
							{return 1;}
					}
				if(input2[i].compare("write")==0)
					{
         				flag=1;
	 					if(user_level<=object_level)
							{return 1;}
					}
			}
	}
if(flag==0) return 1;
return 0;
}
int check_rbac()
{
	int rbac_found=0;
	int r=0,c=0;
	//cout<<"hello";
 	for(int i=0;i<total_input;i++)
 	{
               //cout<<input1[i];
               if(input1[i].compare("Action")==0)
			{current_activity=input2[i]; 
			 //cout<<current_activity_r;
                         }
		else if(input1[i].compare("Role")==0)
			{current_role=input2[i]; 
			 //cout<<current_role_r;
                         }
               
               if(input1[i].compare("Object")==0)
			{
			current_obj=input2[i];
			//cout<<current_obj_r;
			}
		if(input1[i].compare("Subject")==0)
			{
			current_user=input2[i];
			//cout<<current_obj_r;
			}
	}
	for(int i=0;i<=Rbac_roles;i++)
		if(current_role.compare(RbacRoleActivity[i][0])==0)
			{
			 r=i;
			//cout<<"found"<<r;			
			}
	for(int i=0;i<=Rbac_act_cols;i++)
		if(current_obj.compare(RbacRoleActivity[0][i])==0)
			{
			 c=i;
			//cout<<"found"<<cont_col;
			}
	for(int i=0;i<=Rbac_roles;i++)    ////     usertorole assignment
		if(current_role.compare(RbacUserRole[i][0])==0)
			{
			 for(int j=0;RbacUserRole[i][j].compare("")!=0;j++)
				{
					if(current_user.compare(RbacUserRole[i][j])==0)
						{rbac_found=1;}
					
				}
						
			}
     // cout<<"hi"<<dac[cont_row][cont_col]<<" j\n";
      // cout<<" curent"<<cont_row<<" "<<cont_col;
	std::size_t found = RbacRoleActivity[r][c].find(current_activity);
	if (found!=std::string::npos)
               { 
		if(rbac_found) 
                return 1;
		
              }		
 return 0;
}
int check_dac()
{
	//cout<<"hello";
 	for(int i=0;i<total_input;i++)
 	{
		if(input1[i].compare("Subject")==0)
			{current_user=input2[i]; 
			// cout<<current_user;
                         }
		if(input1[i].compare("Object")==0)
			{
			current_obj=input2[i];
			//cout<<current_obj;
			}
		if(input1[i].compare("Action")==0)
			{
			current_activity=input2[i];
			//cout<<current_activity;
			}
	}
	for(int i=0;i<=total_users;i++)
		if(current_user.compare(DACtable[i][0])==0)
			{
			 cont_row_in_dac=i;
			//cout<<"found"<<cont_row;			
			}
	//cout<<objects;
	for(int i=1;i<=total_objects;i++)
		{
		//cout<<current_obj<<" "<<dac[0][i]<<" "<<endl;
		if(current_obj.compare(DACtable[0][i])==0)
			{
			 cont_col_in_dac=i;
			//cout<<"found"<<cont_col;
			}
		}
     // cout<<"hi"<<dac[cont_row][cont_col]<<" j\n";
      // cout<<" curent"<<cont_row<<" "<<cont_col;
       std::size_t found = DACtable[cont_row_in_dac][cont_col_in_dac].find(current_activity);
       if (found!=std::string::npos)
               {
                //cout<<"found";
                return 1;
		
              }		
 return 0;
}
int found_pos(string a, int pos)
{
	//cout<<current_activity<<"*";
	//cout<<a<<endl;
       int temp;
//	current_activity="sejal";
//	int len_act=a.length();
	int len_current=current_activity.length();
//	int j=0;
//	int i;
//	for(i=pos;i<len_current;i++)
//	{
//  	//cout<<"****"<<current_activity[i]<<"* \n";
//		for(int k=0;k<len_act;k++)
//  			{
//                       	//cout<<current_activity[k]<<" * "<<a[i]<<endl;
//			if(a[k]==current_activity[i++])
//				{
//				//cout<<current_activity[j]<<" * "<<a[i]<<endl;
//        			 j++;
//        			 if(j==len_current)
//            			 {return i+1;}
//       			 	}
//  			else 
//				j=0;
//			}
//	}
int j=0;
	for(int i=pos;a[i]!='\0';i++)
		{
       		 j=0;
       		 if(a[i]==current_activity[j])
        		{
           		 temp=i+1;
           		 while(a[i]==current_activity[j])
            			{
               			 i++;
               			 j++;
            			}
 
            if(current_activity[j]=='\0')
            {
               // cout<<"The substring is present in given string at position "<<temp;
                  return temp+1+len_current;
	    }
      }
   }
//cout<<"hhhhhh";
return 0;
}
int check_cons(int x)
{
	int a=0,b=0;
	for(int i=0;Attributetable[x][i].compare("")!=0;i++)
    	 {
 		a++;
		//cout<<att[x][i];
	
		for(int j=0;j<total_input;j++)
			{               
		
				if(Attributetable[x][i].compare(input1[j])==0 && Attributetable[x][++i].compare(input2[j])==0)
		       			 { 
					b++; 
					//cout<<input1[j]<<" "<<input2[j];
					}	
			}
     	}
	//cout<<a<<" "<<b;
	if(a==b)
		return 1;
	return 0;
}

int check_att()
{
	int x,start=0,flag=0;
	int temp=dac2[cont_row_in_dac-1][cont_col_in_dac-1];
	int len_act=arraycheck[temp].length();
	//cout<<arraycheck[temp];
	int temp1;
	while(1)
	{
		temp1=found_pos(arraycheck[temp],start);
		//cout<<arraycheck[temp]<<"****"<<start;
		//cout<<" *"<<start<<"* ";
		if(temp1==0)
       		{
			//cout<<"here";
			break;
	 	}
  		else
      		{
       		 	//cout<<"hi";
        		string temps;
			for(int i=temp1;arraycheck[temp][i]!=',';i++)
				{
				temps+=arraycheck[temp][i];
				}
			//cout<<temps;
			stringstream geek(temps);
			geek >> x;
			int ans=check_cons(x);
			if(ans==1)
				{
				//cout<<"found";
				flag=1;
				return 1;break;
				}
			else
				start=temp1;
      		}
	}
	if(flag)
		return 1;
return 0;
}


int main(int argc,char *argv[])
{
	initialize();
	get_inputQuery(argv[1]);
	//print_Query();
	get_metadata(argv[2]);
	//print_initial_DecisionTable();
	print_initial_DecisionTable_tofile();
	get_policy(argv[3]);
	print_final_DecisionTable_tofile();
	get_objects();
	get_users();
	generate_dac2();
	//printdac2();
	create_DACtable();
	print_DACtable();
	//print_array_tobe_checked();
	print_attribute_constraint();
	intial_mac();
	get_rbac_user(argv[4]);
	print_RbacUser();
	get_RbacAct(argv[5]);
	print_RbacAct();
	int myans1=check_mac();
	int myans4=check_rbac();
	int myans2=check_dac();
	//int n=found_pos("sejalpatelsejalpatel",7);
	//cout<<n;
	int myans3=check_att();
	if(!myans1)cout<<"permission denied by MAC";
	
	else if(!myans4)cout<<"permission denied by RBAC";
	
	else if(!myans2)cout<<"permission denied by DAC";
	
	else if(!myans3)cout<<"permission denied by Attributes";
	else cout<<"permission granted";
		
return 0;
}
