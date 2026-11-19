package dz.univ.threat;

import dz.univ.threat.model.InputType;
import dz.univ.threat.model.ScanItem;
import dz.univ.threat.model.ScanResult;
import dz.univ.threat.service.MessageRuleAnalyzer;

/** Quick console test for Person 3: run it to see the analyzer working (no window needed). */
public class Main {
    public static void main(String[] args) {
        MessageRuleAnalyzer analyzer = new MessageRuleAnalyzer();

        String[] messages = {
                "Your lab appointment is confirmed for tomorrow at 2:00 PM",                                  // row 6
                "Notice: Account verification required within 24 hours. Visit http://192.168.1.50/verify to prevent suspension.", // row 7
                "Please review your weekly account digest and notification settings.",                         // row 8
                "",                                                                                           // row 10
                "Send me your OTP right now",
                "Votre compte sera suspendu. Envoyez votre mot de passe immédiatement.",
                "عاجل: سيتم تعليق حسابك، أرسل كلمة السر الآن"
        };

        int id = 1;
        for (String text : messages) {
            ScanResult r = analyzer.analyze(new ScanItem(id++, InputType.MESSAGE, text));
            System.out.println("#" + (id - 1) + " \"" + text + "\"");
            System.out.println("   -> " + r.level() + "  score=" + r.score()
                    + (r.error() != null ? "  error=" + r.error() : ""));
            r.reasons().forEach(reason -> System.out.println("      - " + reason));
        }
    }
}
