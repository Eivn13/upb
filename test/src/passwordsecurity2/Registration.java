//////////////////////////////////////////////////////////////////////////
// TODO:                                                                //
// Uloha1: Do suboru s heslami ulozit aj sal. DONE                      //
// Uloha2: Pouzit vytvorenu funkciu na hashovanie a ulozit heslo        //
//         v zahashovanom tvare.                          DONE          //
//////////////////////////////////////////////////////////////////////////
package passwordsecurity2;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.passay.CharacterRule;
import org.passay.DictionaryRule;
import org.passay.EnglishCharacterData;
import org.passay.LengthRule;
import org.passay.PasswordData;
import org.passay.PasswordValidator;
import org.passay.RuleResult;
import org.passay.dictionary.WordListDictionary;
import org.passay.dictionary.WordLists;
import org.passay.dictionary.sort.ArraysSort;

import passwordsecurity2.Database.MyResult;
import passwordsecurity2.Security;


public class Registration {
    protected static MyResult registracia(String meno, String heslo) throws NoSuchAlgorithmException, Exception{
        if (Database.exist("hesla.txt", meno)){
            System.out.println("Meno je uz zabrate.");
            return new MyResult(false, "Meno je uz zabrate.");
        }
        else if (!passayValidator(heslo)) {
        	return new MyResult(false, "Prilis slabe heslo.");
        }
        else {
            /*
            *   Salt sa obvykle uklada ako tretia polozka v tvare [meno]:[heslo]:[salt].
            */
        	String hashHeslo = Security.generatePswd(heslo);
            Database.add("hesla.txt", meno + ":" + hashHeslo);
        }
        return new MyResult(true, "");
    }
    
    protected static boolean passayValidator(String heslo) throws FileNotFoundException, IOException {
    	DictionaryRule dictRule = new DictionaryRule(
    			new WordListDictionary(WordLists.createFromReader(
    					new FileReader[] {new FileReader("..\\src\\dict")},
    					false, //case sensitivity
    					new ArraysSort())));
    	
    	PasswordValidator pswdValidator = new PasswordValidator(
    			new LengthRule(8), //dlzka hesla
    			new CharacterRule(EnglishCharacterData.Digit, 3),
    			new CharacterRule(EnglishCharacterData.UpperCase, 1),
    			new CharacterRule(EnglishCharacterData.Special, 1)
    			);

    	RuleResult result = pswdValidator.validate(new PasswordData(heslo));
    	if(result.isValid()) {
    		RuleResult result1 = dictRule.validate(new PasswordData(heslo));
    		if(result1.isValid()) {
    			return true;
    		}
    	}
		return false;
    }
    
}
