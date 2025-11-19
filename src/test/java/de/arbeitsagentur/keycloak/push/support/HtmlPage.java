package de.arbeitsagentur.keycloak.push.support;

import org.jsoup.nodes.Document;

import java.net.URI;

public record HtmlPage(URI uri, Document document) {
}
