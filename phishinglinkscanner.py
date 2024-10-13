import re

sus_links_re = [
    (r'http://', 1),
    (r'-', 1),
    (r'\d+', 1),
    (r'[@%&]', 1),
] #this is a regular expression that checks for patterns of an ideal phishing link and it also has the risk score next to each other

not_sus_links = re.compile(r'''
    \.(com|org|co|net|gov|edu|io|info|blog|me|biz|store)$  
''', re.VERBOSE)
#this is a regular expression to check for known safe domain extension 

def isphishing(url): #this calculates the risk score of the given url
    risk = 0
    for sus, score in sus_links_re:
        if re.search(sus, url):
            risk += score
    if not not_sus_links.search(url):
        risk += 2

    return risk

url = input('Enter your URL to check: \n') #this gets the url from the user
risk = isphishing(url) #calls the function to calculate the risk score and store it in this variable


if risk >= 3: #here it gives the risk score of the url to the user and provides feedback based on the risk score 
    print(f"High Risk: This URL has a risk score of {risk}. It is likely to be a phishing link. Please do not click it. Always use official links.")
elif risk == 2:
    print(f"Moderate Risk: This URL has a risk score of {risk}. Be cautious, it shows some suspicious signs. Don't enter any personal information in this website.")
else:
    print(f"Low Risk: This URL has a risk score of {risk}. The URL seems safe, but always proceed with caution.")
