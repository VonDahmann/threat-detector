// Root package of the project. This file was called "Main" in your zip, but Person 1 owns the real
// Main.java (the one that opens the window). Two classes with the same name would collide when
// you merge, so your console test now has its own name: MessageAnalyzerDemo.
package dz.univ.threat;

import dz.univ.threat.model.InputType;          // URL or MESSAGE
import dz.univ.threat.model.ScanItem;           // the thing to scan
import dz.univ.threat.model.ScanResult;         // the answer
import dz.univ.threat.service.MessageRuleAnalyzer; // the class we want to try

/**
 * Quick console test for Person 3: run it to see the analyzer working (no window needed).
 * The guide says: "Test the backend from a simple console Main before touching the UI."
 * It is NOT part of the final app, you can keep it or delete it.
 */
public class MessageAnalyzerDemo {

    // Entry point: Java starts here when you run this class.
    public static void main(String[] args) {
        // Create ONE analyzer; it has no state, so it can be reused for every message.
        MessageRuleAnalyzer analyzer = new MessageRuleAnalyzer();

        // The messages to try (the dataset rows 6, 7, 8, 10 first, then FR / AR / EN examples).
        String[] messages = {
                "Your lab appointment is confirmed for tomorrow at 2:00 PM",                                  // row 6  -> Low
                "Notice: Account verification required within 24 hours. Visit http://192.168.1.50/verify to prevent suspension.", // row 7 -> High
                "Please review your weekly account digest and notification settings.",                         // row 8  -> Medium
                "",                                                                                           // row 10 -> Not Verified
                "Send me your OTP right now",                                                                 // asks for a secret
                "Votre compte sera suspendu. Envoyez votre mot de passe immédiatement.",                      // French
                "عاجل: سيتم تعليق حسابك، أرسل كلمة السر الآن"                                                  // Arabic
        };

        // Ids start at 1, like the rows of the dataset.
        int id = 1;
        // Scan every message one after the other.
        for (String text : messages) {
            // Wrap the text into a ScanItem (id, type MESSAGE, content) and analyze it.
            // "id++" uses the current id and then adds 1 for the next message.
            ScanResult r = analyzer.analyze(new ScanItem(id++, InputType.MESSAGE, text));
            // Print the id (id - 1 because we already incremented it) and the message.
            System.out.println("#" + (id - 1) + " \"" + text + "\"");
            // Print the level and the score; add the error text only when there is one.
            System.out.println("   -> " + r.level() + "  score=" + r.score()
                    + (r.error() != null ? "  error=" + r.error() : ""));
            // Print each reason on its own line (the lambda "reason -> ..." runs once per reason).
            r.reasons().forEach(reason -> System.out.println("      - " + reason));
        }
    }
}
