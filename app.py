

def find_vendor(query):
    macbook = {}

    #Opens the txt file with list OUI
    with open('./oui-2.txt','r',encoding='utf-8') as f:
        content = f.readlines()

    #makes a dictonary of MAC IDs as keys and Vendor as Values
    for i in range(4,len(content),6):
        j = i+1
        oui = str(*content[i:j])
        macbook[oui[:8]]=oui[18:]

    
    #returns the output for the query
    return(macbook.get(query))


if __name__ == '__main__':
    print("\n-----Organisationally Unique Identifier-----\n\nTo Search enter first three octec of MAC address\n-> Ex: 00-40-96\nTo quit enter = q\n")
    

    while(True):
        query = input("Enter: ")
        #query = query.replace("-",":")
        if query == 'q':    
            break;
        else:
            print(find_vendor(query.upper()[:8]))