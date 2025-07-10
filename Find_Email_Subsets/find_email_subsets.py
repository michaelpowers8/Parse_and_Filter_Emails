import os
import re
import json
import bisect
import hashlib
import traceback
import numpy as np
from tqdm import tqdm
from typing import Any
from collections import defaultdict
from xml_logging import XML_Logger
from difflib import SequenceMatcher
from pandas import DataFrame,read_json
LOGGER_DIRECTORY:str = os.path.dirname(os.path.abspath(__file__))

def remove_emails_from_body(text:str) -> str:
    email_pattern: re.Pattern = re.compile(r'(?:<)?(?:mailto:)?[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:>)?')
    text:str = re.sub(email_pattern,"",text)
    return text
        
def remove_links_from_body(text:str) -> str:
    https_pattern:re.Pattern = re.compile(r"https?:.+?[\s\n\r\t]{1}")
    www_pattern:re.Pattern = re.compile(r"www\..+?[\s\n\r\t]{1}")
    text:str = re.sub(https_pattern,"",text)
    text:str = re.sub(www_pattern,"",text)
    return text
        
def clean_text(text:str,logger:XML_Logger):
    try:
        text:str = remove_emails_from_body(text)
        text:str = remove_links_from_body(text)
        return text
    except Exception as e:
        logger.log_to_xml(message=f"Failed to clean email body text. Official error: {traceback.format_exc()}",basepath=logger.base_dir,status="Error")
        return text

def hash_eml_body(eml_body:str,logger:XML_Logger) -> str:
    try:
        encoded_body:str = eml_body.encode('utf-8')
        hash_object = hashlib.sha256(encoded_body)
        return hash_object.hexdigest()
    except Exception as e:
        logger.log_to_xml(message=f"Failed to hash email body. Official error: {traceback.format_exc()}",basepath=logger.base_dir,status="Error")
        return "Unhashable"

def get_full_data(data_path:str, logger:XML_Logger) -> np.ndarray|None:
    try:
        df:DataFrame = read_json(data_path)
        df["Body_Length"] = df["Body"].str.len()
        full_data:np.ndarray = df.sort_values(by=["Email_Date","Body_Length"],ascending=[True,False]).to_numpy()
        return full_data
    except Exception as e:
        logger.log_to_xml(message=f"Failed to get full dataset. Terminating program. Official error: {traceback.format_exc()}",basepath=logger.base_dir,status="CRITICAL")
        return None

def save_data(data:list[list[int|str]],columns:list[str]):
    df:DataFrame = DataFrame(data,columns=columns)
    df.to_json(
            path_or_buf="Cleaned_Email_Data.json",
            mode='w',
            lines=True,
            orient='records',
            indent=4
        )
    df.to_csv(
            path_or_buf="Cleaned_Email_Data.csv",
            mode='w',
            index=False
        )

def is_contained(email_path:str,raw_bodies:list[str],cleaned_bodies:list[str],current_body:str,current_cleaned_body:str,logger:XML_Logger):
    try:
        for raw, cleaned in zip(raw_bodies, cleaned_bodies):
            if ((len(current_body) > len(raw)) or (len(current_cleaned_body) > len(cleaned))):
                continue # Current email is longer than previously stored email. Impossible for it to be a subset
            if (current_body in raw) or (current_cleaned_body in cleaned):
                logger.log_to_xml(message=f"{email_path} is an exact match of another email. Not adding to the final set.",basepath=logger.base_dir,status="INFO")
                return True # Current email is an exact replica of a previously stored email. Skipping
            if (is_similar(raw,current_body)) or (is_similar(cleaned,current_cleaned_body)):
                logger.log_to_xml(message=f"{email_path} is over 90% similar to another email. Not adding to the final set.",basepath=logger.base_dir,status="INFO")
                return True # Current email is similar enough to a previously stored email that it can be skipped
        return False
    except Exception as e:
        logger.log_to_xml(message=f"Failed to check if email is contained in another email",basepath=logger.base_dir,status="WARN")
        return False

def is_contained_optimized(email_path: str, raw_bodies: list[str], cleaned_bodies: list[str], 
                         current_body: str, current_cleaned_body: str, logger: XML_Logger,
                         length_index: dict[int, list[int]], threshold=0.9) -> bool:
    """
    Optimized version of is_contained that:
    1. Uses length-based indexing to reduce comparisons
    2. Implements early exit strategies
    3. Reduces redundant similarity calculations
    """
    try:
        current_len:int = len(current_body)
        
        # Get candidate indices based on length (only emails longer than current)
        candidate_indices = []
        for key,item in length_index.items():
            if key >= current_len:
                candidate_indices.extend(item)
        
        # Deduplicate and sort indices
        candidate_indices = sorted(set(candidate_indices))
        
        for idx in candidate_indices:
            raw = raw_bodies[idx]
            cleaned = cleaned_bodies[idx]
            
            # Exact match check
            if current_body in raw or current_cleaned_body in cleaned:
                logger.log_to_xml(
                    message=f"{email_path} is an exact match of another email. Not adding to final set.",
                    basepath=logger.base_dir,
                    status="INFO"
                )
                return True
                
            # Similarity check (only if lengths are close)
            if abs(len(raw) - current_len) / max(len(raw), current_len) < 0.2:  # Lengths within 20%
                if is_similar(raw, current_body, threshold) or is_similar(cleaned, current_cleaned_body, threshold):
                    logger.log_to_xml(
                        message=f"{email_path} is over {threshold*100:.0f}% similar to another email. Not adding to final set.",
                        basepath=logger.base_dir,
                        status="INFO"
                    )
                    return True
                    
        return False
    except Exception as e:
        logger.log_to_xml(
            message=f"Failed to check if email {email_path} is contained in another email. Number of possible emails: {len(raw_bodies):,.0f}. {length_index}. Official error: {traceback.format_exc()}",
            basepath=logger.base_dir,
            status="WARN"
        )
        return False

def is_similar(text1:str, text2:str, threshold=0.9):
    return SequenceMatcher(None, text1, text2).ratio() >= threshold

def _verify_configuration(configuration:dict[str,str|int|float]) -> bool:
    try:
        required_keys:list[str] = ["Original_Data_Path"]
        missing_keys:list[str] = []
        for key in required_keys:
            if key not in configuration.keys():
                missing_keys.append(key)
        if len(missing_keys) > 0:
            print(f"""Configuration is missing the keys \"{",".join(missing_keys)}\". Terminating program.""")
            return False
        else:
            return True
    except Exception as e:
        print(f"Failed to verify configuration. Terminating program. Official error: {traceback.format_exc()}")
        return False

def get_configuration() -> dict[str,str|int|float]|None:
    try:
        with open("find_email_subset_configuration.json","r",encoding='utf-8') as file:
            configuration:dict[str,str|int|float] = json.load(file)
        if not(_verify_configuration(configuration)):
            return None
        else:
            return configuration
    except Exception as e:
        print(f"Configuration failed to load. Terminating program. Official error: {traceback.format_exc()}")
        return None

def main():
    configuration:dict[str,str|int|float]|None = get_configuration()
    if configuration is None:
        return
        
    logger:XML_Logger = XML_Logger(
            log_file="Email_Subset_Logger",
            archive_folder="archive",
            log_retention_days=7,
            base_dir=LOGGER_DIRECTORY
        )
    
    full_data:np.ndarray|None = get_full_data(data_path=configuration["Original_Data_Path"], logger=logger)
    if full_data is None:
        return
        
    columns:list[str] = ["ATG_Ref", "FilePath", "Email_Date", "From", "To", "CC", "BCC", 
              "Subject", "Body", "HASH_Body", "Body_Length"]
    
    cleaned_data:list[str] = []
    raw_eml_bodies:list[str] = []
    cleaned_eml_bodies:list[str] = []
    unique_body_hashes:set[str] = set()  # Using set for O(1) lookups
    length_index:defaultdict[Any,list] = defaultdict(list)  # Maps body length to list of indices
    
    for i, row in enumerate(tqdm(full_data)):
        text:str = row[columns.index("Body")]
        cleaned_text:str = clean_text(text, logger=logger)
        cleaned_hash:str = hash_eml_body(cleaned_text, logger=logger)
        
        # Skip if hash exists
        if cleaned_hash in unique_body_hashes:
            continue
            
        email_path:str = str(row[1]).replace('/', '\\')
        
        # Only check containment if we have previous emails
        if raw_eml_bodies:
            if is_contained_optimized(
                email_path, raw_eml_bodies, cleaned_eml_bodies,
                text, cleaned_text, logger, length_index
            ):
                continue
                
        cleaned_data.append([
            row[columns.index("ATG_Ref")], email_path, row[columns.index("Email_Date")], 
            row[columns.index("From")], row[columns.index("To")], row[columns.index("CC")], 
            row[columns.index("BCC")], row[columns.index("Subject")], text, cleaned_hash, row[columns.index("Body_Length")]
        ])
        unique_body_hashes.add(cleaned_hash)
        raw_eml_bodies.append(text)
        cleaned_eml_bodies.append(cleaned_text)
        length_index[len(text)].append(len(raw_eml_bodies)-1)
    
    save_data(cleaned_data, columns)
    print(f"Original emails: {len(full_data)}")
    print(f"Unique emails: {len(cleaned_data)}")
    
    logger.log_to_xml(message=f"Successfully made email data with only unique emails.",basepath=logger.base_dir,status="SUCCESS")
    logger.save_variable_info(
            globals_dict=globals(),
            locals_dict=locals(),
            variable_save_path="find_email_subset_variables.json"
        )

if __name__ == "__main__":
    main()