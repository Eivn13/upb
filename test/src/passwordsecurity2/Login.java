//////////////////////////////////////////////////////////////////////////
// TODO:                                                                //
// Uloha2: Upravte funkciu na prihlasovanie tak, aby porovnavala        //
//         heslo ulozene v databaze s heslom od uzivatela po            //
//         potrebnych upravach.                                    DONE //
// Uloha3: Vlozte do prihlasovania nejaku formu oneskorenia.       DONE //
//////////////////////////////////////////////////////////////////////////
package passwordsecurity2;

import java.io.IOException;
import java.util.StringTokenizer;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

import passwordsecurity2.Database.MyResult;

@WebServlet("/login")
public class Login extends HttpServlet {
    protected static MyResult prihlasovanie(String meno, String heslo) throws IOException, Exception{
        /*
        *   Delay je vhodne vytvorit este pred kontolou prihlasovacieho mena.
        *   team - mame vo validacnej metode, kniznica tak povedala
        */
        MyResult account = Database.find("hesla.txt", meno);
        if (!account.getFirst()){
            return new MyResult(false, "Nespravne meno.");
        }
        else {
            StringTokenizer st = new StringTokenizer(account.getSecond(), ":");
            st.nextToken();      //prvy token je prihlasovacie meno
            /*
            *   Pred porovanim hesiel je nutne k heslu zadanemu od uzivatela pridat prislusny salt z databazy a nasledne tento retazec zahashovat.
            */
            
            boolean rightPassword = Security.validatePswd(st.nextToken(), heslo);
            if (!rightPassword)    
                return new MyResult(false, "Nespravne heslo.");
        }
        return new MyResult(true, "Uspesne prihlasenie.");
    }
}
