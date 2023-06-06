package org.kocakosm.test.owasp.html;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

/**
 * OWASP HTML sanitizer tests.
 *
 * @author Osman Koçak
 */
public final class HtmlSanitizationTest
{
    @ParameterizedTest
    @MethodSource("html5InlineFormattingElements")
    public void testAllowCommonInlineFormattingElementsWithCustomPolicy(String element)
    {
        String html = String.format("<%1$s>Hi!</%1$s>", element);
        PolicyFactory policy = new HtmlPolicyBuilder().allowElements(element).toFactory();
        assertEquals(html, policy.sanitize(html));
    }

    @ParameterizedTest
    @MethodSource("html5InlineFormattingElements")
    public void testAllowCommonInlineFormattingElementsWithBuiltinPolicy(String element)
    {
        String html = String.format("<%1$s>Hi!</%1$s>", element);
        PolicyFactory policy = Sanitizers.FORMATTING;
        assertEquals(html, policy.sanitize(html));
    }

    private static Stream<String> html5InlineFormattingElements()
    {
        return Stream.of(
            "b", "i", "s", "u", "sup", "sub", "ins",
            "del", "strong", "code", "small", "em", "span"
        );
    }
}
