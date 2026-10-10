// Package checks ist der Check-Bot: ein Interface und je Check-Typ eine Datei.
//
// Das Paket hat bewusst keine Abhaengigkeit zu web, store, scheduler oder
// notify, damit derselbe Code spaeter unveraendert auf den ipv64-Servern
// laeuft. Umsetzung folgt in Phase 2.
package checks
