import os
import json
import hashlib
import traceback
from pandas import DataFrame
from bs4 import BeautifulSoup
from xml_logging import XML_Logger
from warnings import filterwarnings
from email.parser import BytesParser
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from email.policy import default as POLICY_DEFAULT
from io import BytesIO
from datetime import datetime
from mailparser import parse_from_string,MailParser
filterwarnings('ignore')
BASE_DIR:str = os.path.dirname(os.path.abspath(__file__))

def clear_console():
    command = 'cls' if os.name == 'nt' else 'clear'
    os.system(command)

def get_eml_date(eml_file_path:str,logger:XML_Logger) -> str:
    """
    Extracts and parses the 'Date' header from an EML file.

    Args:
        eml_file_path (str): The path to the EML file.

    Returns:
        datetime.datetime or None: A datetime object representing the email's date,
                                   or None if the 'Date' header is not found or cannot be parsed.
    """
    try:
        with open(eml_file_path, 'rb') as fp:
            msg:BytesParser = BytesParser(policy=POLICY_DEFAULT).parse(fp)
            
            date_header:str = msg['Date']
            if date_header:
                # parsedate_to_datetime handles various email date formats and timezones
                return parsedate_to_datetime(date_header).strftime("%Y-%m-%d")
            else:
                return ""
    except FileNotFoundError:
        logger.log_to_xml(message=f"Error: EML file not found at {eml_file_path}",basepath=logger.base_dir,status="ERROR")
        return ""
    except Exception as e:
        logger.log_to_xml(message=f"An error occurred while parsing the EML file: {e}",basepath=logger.base_dir,status="ERROR")
        return ""

def receivers(raw_email:str,logger:XML_Logger) -> dict[str,str]:
    receivers:dict[str,list[str]] = {}
    receivers["to"] = []
    receivers["cc"] = []
    receivers["bcc"] = []
    try:
        parsed_email:MailParser = parse_from_string(raw_email)
        to = parsed_email.to_
        if(len(to) > 0): # Check if the email was sent to anybody at all
            if(isinstance(to,list)):
                for t in to: 
                    if(len(t[1]) > 0): # Ensure there is an existing email
                        receivers["to"].append(t[1])
                receivers["to"] = "|".join(receivers["to"])
            elif(isinstance(to,str)):
                receivers["to"] = to
            else:
                receivers["to"] = str(to)
        else:
            receivers["to"] = ""
        
        cc = parsed_email.cc_
        if(len(cc) > 0): # Check if the email was cc'd to anybody 
            if(isinstance(cc,list)):
                for c in cc: 
                    if(len(c[1]) > 0): # Ensure there is an existing email
                        receivers["cc"].append(c[1])
                receivers["cc"] = "|".join(receivers["cc"])
            elif(isinstance(cc,str)):
                receivers["cc"] = cc
            else:
                receivers["cc"] = str(cc)
        else:
            receivers["cc"] = ""

        bcc = parsed_email.bcc_
        if(len(bcc) > 0): # Check if the email bcc'd to anybody
            if(isinstance(bcc,list)):
                for b in bcc: 
                    if(len(b[1]) > 0): # Ensure there is an existing email
                        receivers["bcc"].append(b[1])
                receivers["bcc"] = "|".join(receivers["bcc"])
            elif(isinstance(bcc,str)):
                receivers["bcc"] = bcc
            else:
                receivers["bcc"] = str(bcc)
        else:
            receivers["bcc"] = ""

        return receivers
    except Exception as e:
        logger.log_to_xml(message=f"Error getting receivers from \"{' '.join(raw_email.split()[:15])}...\". Official error thrown: {traceback.format_exc()}",basepath=logger.base_dir,status="WARN")
        return receivers

def sender(raw_email:str,logger:XML_Logger) -> dict[str,str]:
    senders:dict[str,list[str]] = {}
    senders["from"] = []
    try:
        parsed_email:MailParser = parse_from_string(raw_email)
        sender = parsed_email.from_
        if(len(sender) > 0 and isinstance(sender,list)): # Check if the email was sent to anybody at all
            for s in sender: 
                if(len(s[1]) > 0): # Ensure there is an existing email
                    senders["from"].append(s[1])
            senders["from"] = "|".join(senders["from"])
        elif((isinstance(sender,str)) and (len(sender) > 0)):
            senders["from"] = sender
        elif(len(sender) > 0):
            senders["from"] = str(sender)
        else:
            senders["from"] = ""
        
        return senders
    except Exception as e:
        logger.log_to_xml(message=f"Error getting the sender of the email from \"{' '.join(raw_email.split()[:15])}...\". Setting sender value to null. Official error: {traceback.format_exc()}",basepath=logger.base_dir,status='WARN')
        senders["from"] = ""
        return senders

def subject(raw_email:bytes,file_name:str,logger:XML_Logger) -> str:
    try:
        if raw_email is None:
            logger.log_to_xml(message=f"Empty or unreadable email at {file_name}. No subject being returned.",basepath=logger.base_dir,status="WARN")
            return ""
        
        parsed_email:MailParser = parse_from_string(raw_email.decode(errors="replace"))
        all_subjects = parsed_email.subject_
        if isinstance(all_subjects,list):
            return ",".join(all_subjects)
        if isinstance(all_subjects,str): # Check if the email was sent to anybody at all
            return all_subjects
        if all_subjects is not None:
            return str(all_subjects)
        return ""
    except Exception as e:
        logger.log_to_xml(message=f"Error getting subject from {file_name}. Official error thrown: {traceback.format_exc()}",basepath=logger.base_dir,status="WARN")
        return ""

def body(file:BytesIO,file_name:str,logger:XML_Logger) -> str:
    """
    Extract just the plain text body of an email (ignoring HTML and other parts).
    This function will only decode content if its MIME type is "text/plain".
    """
    try:
        msg:EmailMessage = BytesParser(policy=POLICY_DEFAULT).parse(file)
        text_content:list[str] = []
        
        for part in msg.walk():
            content_type = part.get_content_type()
            charset = part.get_content_charset() or 'utf-8'

            if content_type == "text/plain":
                text_content.append(part.get_payload(decode=True).decode(charset, errors='ignore'))
            
            elif content_type == "text/html":
                html_content = part.get_payload(decode=True).decode(charset, errors='ignore')
                soup:BeautifulSoup = BeautifulSoup(html_content, 'html.parser')

                # Remove scripts, styles, and non-visible elements
                for tag in soup(["script", "style", "a", "head", "title", "meta", "link"]):
                    tag.decompose()

                # Extract only visible text
                body_text = soup.get_text(separator="\n").strip()
                text_content.append(body_text)

        # Filtering out email metadata and empty lines
        ignored_prefixes = {"FROM:", "TO:", "CC:", "BCC:", "SENT:", "SUBJECT:"}
        final_lines = [
                line.lstrip("<").lstrip("*").strip()
                for context in text_content
                for line in context.split("\n")
                if not any(prefix in line[:10].upper() for prefix in ignored_prefixes) and line.strip()
            ]

        final_lines:str = '\n'.join(final_lines)

        return final_lines
    except Exception as e:
        logger.log_to_xml(f"Failed to extract email text from {file_name}. Official error: {traceback.format_exc()}",basepath=logger.base_dir,status="ERROR")
        return "" 

def verify_configuration(configuration:dict[str,str]) -> bool:
    required_keys:list[str] = ["Email_Directories","Restart_Email_Parsing","Parsed_Email_Save_Folder"]
    missing_keys:list[str] = []
    for key in required_keys:
        if(key not in configuration.keys()):
            missing_keys.append(key)
    if(len(missing_keys) > 0):
        if("Logging_Basepath" in missing_keys):
            XML_Logger("Email_Parsing_Log",archive_folder="archive",log_retention_days=7,base_dir=BASE_DIR).log_to_xml(message=f"Configuration is missing the required keys {','.join(missing_keys)}. Program will now be terminated",basepath=BASE_DIR,status="CRITICAL")
        else:
            XML_Logger("Email_Parsing_Log",archive_folder="archive",log_retention_days=7,base_dir=BASE_DIR).log_to_xml(message=f"Configuration is missing the required keys {','.join(missing_keys)}. Program will now be terminated",basepath=BASE_DIR,status="CRITICAL")
        return False
    return True

def load_configuration(config_path:str) -> dict[str,str]|None:
    with open(config_path,"rb") as file:
        configuration:dict[str,str] = json.load(file)

    if(not(verify_configuration(configuration=configuration))):
        return None
    
    return configuration

def merge_eml_parts_to_string(eml_date:str,senders:str,to_receivers:str,cc_receivers:str,bcc_receivers:str,eml_subjects:str,eml_body:str):
    full_eml_body:str = f"""
DATE: {eml_date}
FROM: {senders}
TO: {to_receivers}
CC: {cc_receivers}
BCC: {bcc_receivers}
SUBJECT: {eml_subjects}
BODY: {eml_body}"""
    return full_eml_body

def _process_individual_eml_file(file:os.DirEntry[str],email_directory:str,parsed_email_save_folder:str,logger:XML_Logger) -> str:
    try:
        file_name:str = file.name.split('.')[0]
        with open(f"{email_directory}/{file.name}",'rb') as email_file:
            raw_email:bytes = email_file.read()
        senders:dict[str,str] = sender(raw_email=raw_email.decode('utf-8'),logger=logger)
        eml_receivers:dict[str,str] = receivers(raw_email=str(raw_email.decode('utf-8')),logger=logger)
        subjects:str = subject(raw_email=raw_email,file_name=file_name,logger=logger)
        eml_body:str = body(file=BytesIO(raw_email),file_name=file_name,logger=logger)
        eml_date:str = get_eml_date(f"{email_directory}/{file.name}",logger=logger)
        full_parsed_email:str = merge_eml_parts_to_string(eml_date,senders["from"],eml_receivers["to"],eml_receivers["cc"],eml_receivers["bcc"],subjects,eml_body)
        with open(f"{parsed_email_save_folder}/{email_directory.replace('/','-')}-{file_name}.txt",'w',encoding='utf-8',errors='ignore') as email_to_text_file:
            email_to_text_file.write(full_parsed_email)
        return eml_date,senders["from"],eml_receivers["to"],eml_receivers["cc"],eml_receivers["bcc"],subjects,eml_body
    except Exception as exception:
        logger.log_to_xml(message=f"Error while parsing {email_directory}/{file.name.split('.')[0]}.txt. Official error thrown: {traceback.format_exc()}",basepath=logger.base_dir,status="ERROR")
        return ""

def hash_eml_body(eml_body:str):
    encoded_body:str = eml_body.encode('utf-8')
    hash_object = hashlib.sha256(encoded_body)
    return hash_object.hexdigest()

def _save_data(data,directory:str):
    backslash:str = '\\'
    DataFrame(data,columns=["ATG_Ref","FilePath","Email_Date","From","To","CC","BCC","Subject","Body","HASH_Body"])\
        .to_json(
            path_or_buf=f"Email_Data_{directory.replace(backslash,'-').replace('/','-')}.json",
            mode='w',
            lines=True,
            orient='records',
            indent=4
            )

def process_email_directory(email_directory:str,parsed_email_save_folder:str,count:int,write_mode:str,logger:XML_Logger) -> tuple[int,set[str]]:
    logger.log_to_xml(message=f"Begin processing {email_directory}",basepath=logger.base_dir,status="INFO")
    try:
        data:list[list[str|int]] = []
        with os.scandir(email_directory) as entries:
            print(f"Successfully opened {email_directory} at {datetime.now()}")
            logger.log_to_xml(message=f"Successfully opened {email_directory}.",basepath=logger.base_dir,status="INFO")
            for file in entries:
                if file.is_file() and file.name.lower().endswith(".eml"):
                    eml_date,eml_sender,to_receiver,cc_receiver,bcc_receiver,eml_subject,eml_body = _process_individual_eml_file(
                                file=file,
                                email_directory=email_directory,
                                parsed_email_save_folder=parsed_email_save_folder,
                                logger=logger
                            )
                    try:
                        data.append([count,os.path.join(email_directory,file.name),eml_date,eml_sender,to_receiver,cc_receiver,bcc_receiver,eml_subject,eml_body,hash_eml_body(eml_body)])
                        count += 1
                    except:
                        pass
                if(
                    (count > 0)and
                    (count%10_000 == 0)
                ):
                    clear_console()
                    print(f"Files Read: {count:,}")
                    logger.log_to_xml(message=f"Files Read: {count:,}",basepath=logger.base_dir,status="INFO")
                    _save_data(data,email_directory)
        _save_data(data,email_directory)
        logger.log_to_xml(f"Finished processing {email_directory}",basepath=logger.base_dir,status="INFO")
        return count
    except:
        logger.log_to_xml(f"Error processing {email_directory}. Official error: {traceback.format_exc()}",basepath=logger.base_dir,status="ERROR")
        return count

def main():
    logger:XML_Logger = XML_Logger("Email_Parsing_Log",archive_folder="archive",log_retention_days=7,base_dir=BASE_DIR)
    logger.log_to_xml(message=f"Begin parsing email files to csv and json.",basepath=logger.base_dir,status="INFO")
    configuration:dict[str,str]|None = load_configuration(os.path.join(BASE_DIR, "Parse_Email_To_Excel_Configuration.json"))
    if configuration is None:
        return

    count:int = 0
    email_directories:list[str] = configuration["Email_Directories"]
    for email_directory in email_directories:
        count = process_email_directory(email_directory=email_directory,parsed_email_save_folder=configuration["Parsed_Email_Save_Folder"],write_mode='w',count=count,logger=logger)
        
    logger.log_to_xml(message=f"Finished parsing email files to csv and json.",basepath=logger.base_dir,status="INFO")
    logger.save_variable_info(globals_dict=globals(),locals_dict=locals(),variable_save_path="Parse_Emails_Variables.json")

if __name__ == "__main__":
    main()