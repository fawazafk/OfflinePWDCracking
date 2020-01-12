/*
Linux offline Password Cracking
Information/Computer Security
Fall 2019
BY:
Fawaz Kserawi - fawazafk@gmail.com
This is an example of old linux password cracking (assuming an attacker has access to the pwd file).
Three files are provided: 1) passwd.txt: a list of hashed passwords
                          2) shadow.txt: a list of salted passwords
                          3) wordlist.txt: a list of dictionary password to try
*/
package pwdcrack;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;


public class PwdCrack {

    public static StringBuilder s = new StringBuilder("aaaa");
    public static char[] chars = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    public static char digit = 'a';
    public static MessageDigest md;
    public static byte[] hash;
    public static StringBuilder hexStr;

    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, IOException {

        Scanner sc = new Scanner(System.in);
        System.out.println("Please place the shadow.txt, passwd.txt and wordlist.txt in the current working directory: \n "
                + System.getProperty("user.dir"));
        System.out.println("-------------------------\n Please choose an option: \n 1- Brute Force Attack (This will take a few minutes) \n 2- Dictionary Attack \n 3- Authenticate User \n q- Quit \n -------------------------");
        String choice = sc.nextLine();
        while (!choice.equals("q")) {

            switch (choice) {
                case "1":
                    System.out.println("Paste the user password hash (Ex: 652bf1bbed1563945d187d10971aa437 )");
                    System.out.println("The password is " + BruteForcePass(sc.nextLine()));
                    break;
                case "2":
                    DictionaryAttachk();
                    break;
                case "3":
                    System.out.println("Authenticating: \n Please Enter Username:");
                    String userNameStr = sc.nextLine();
                    System.out.println("Please Enter Password:");
                    String passWordStr = sc.nextLine();
                    System.out.println(Authenticate(userNameStr, passWordStr));
                    break;
                case "q":
                    System.out.println( "Quitting..." );
                    break;
                default:
                    System.out.println("Wrong Choice");
            }
            System.out.println("-------------------------\n Please choose an option: \n 1- Brute Force Attack (This will take a few minutes) \n 2- Dictionary Attack \n 3- Authenticate User \n q- Quit \n -------------------------");
            choice = sc.nextLine();
        }
        System.out.println( "Quitting..." );
    }

//// F:3 Authenticate Users:  
    public static String Authenticate(String userNameStr, String passWordStr) throws IOException {
        BufferedReader reader;
        Map<String, String> userShadowPwd = new HashMap<String, String>();
        String userHash, salt, shadowHash;

        try {
            reader = new BufferedReader(new FileReader("shadow.txt"));
            String line = reader.readLine();
            while (line != null) {
                String[] values = line.split(":");
                String[] subValues = values[1].split("\\$"); //subValues[1]: Salt - subValues[2]: Hash
                salt = subValues[1];
                userHash = md5Java(passWordStr + salt);
                shadowHash = subValues[2];

                if (userHash.equals(shadowHash)) {
                    return ("Login Succeeded");
                }
                line = reader.readLine();
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(PwdCrack.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(PwdCrack.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(PwdCrack.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "Login Failed !!";
    }

//// F:2: Dictionarry attack
    public static void DictionaryAttachk() {
        BufferedReader reader;
        // F: Read wordlist.txt
        try {
            Map<String, String> rainbowTable = new HashMap<String, String>();
            Map<String, String> userPasswordHashes = new HashMap<String, String>();
            reader = new BufferedReader(new FileReader("wordlist.txt"));
            String line = reader.readLine();
            while (line != null) {
                rainbowTable.put(line, md5Java(line));
                //                System.out.println(rainbowTable.get(line));
                line = reader.readLine();
            }
            // Read Usernames/hashes from passwd.txt
            reader = new BufferedReader(new FileReader("passwd.txt"));
            String pwdListLine = reader.readLine();
            while (pwdListLine != null) {
                String[] values = pwdListLine.split(":");
                userPasswordHashes.put(values[0], values[1]);
                pwdListLine = reader.readLine();
            }

            for (String username : userPasswordHashes.keySet()) {
                for (String passwd : rainbowTable.keySet()) {
                    if (rainbowTable.get(passwd).equals(userPasswordHashes.get(username))) {
                        System.out.println("Found username: " + username + " Password: " + passwd + " Hash: " + rainbowTable.get(passwd));
                    }
                }
            }
            reader.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(PwdCrack.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(PwdCrack.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(PwdCrack.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

//// F:1 This Loops through all possible characters combinations
    public static String BruteForcePass(String hashString) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String bruteForcePass = "";
        System.out.println("Trying Generated Passwords:");
        for (int i = 0; i <= (Math.pow(chars.length,s.length())-1); i++) { //start at i = 13055000 for fatima password ends at 14776335 for 4 digits
            if (md5Java(base62(i)).equals(hashString)) {
                bruteForcePass = base62(i);
                return bruteForcePass;
            }
        }
        return "Not Found";
    }
    //Return a base62 string from a 62 char set (the length of our char array)
    public static String base62(int num) {
        if (num < 0) {
            throw new IllegalArgumentException("Only positive numbers are supported");
        }
        for (int pos = s.length() - 1; pos >= 0 && num > 0; pos--) {
            digit = chars[num % 62];
            s.setCharAt(pos, digit);
            num = num / 62;
        }
        return s.toString();
    }

//// Hash a string in MD%
    public static String md5Java(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String digest = null;
        md = MessageDigest.getInstance("MD5");
        hash = md.digest(message.getBytes("UTF-8"));
        //converting byte array to Hexadecimal String
        hexStr = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            hexStr.append(String.format("%02x", b & 0xff));
        }
        digest = hexStr.toString();
        return digest;
    }
}