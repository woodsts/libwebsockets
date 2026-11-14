/*
 * lhp edges and touch page
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * See edges-ui.h
 */

#include "edges-ui.h"
#include <string.h>

/* the inset as it's stored in the settings: its four bytes as they are */
#define EDGES_SETTING		"lhp.inset"

/* the edges' rows, top to bottom, and which of the inset each is */

static const struct {
	const char	*name;
	char		c;	/* in its controls' hrefs */
	uint8_t		idx;	/* in the inset */
} edges[] = {
	{ "Top",	't', 1 },
	{ "Left",	'l', 0 },
	{ "Right",	'r', 2 },
	{ "Bottom",	'b', 3 },
};

static int
clamp(int v, int lo, int hi)
{
	return v < lo ? lo : (v > hi ? hi : v);
}

/* a 1px black line, along an edge of what can be seen or of the cross */

static void
line(lws_html_w_t *w, const char *id, int x, int y, int lw, int lh)
{
	lws_html_w_printf(w, "#%s { left: %dpx; top: %dpx; width: %dpx;"
			     " height: %dpx }", id, x, y, lw, lh);
}

int
lhp_edges_html(char *buf, size_t len, const lws_surface_info_t *ic,
	       const uint8_t inset[4], const lhp_edges_touch_t *t)
{
	int w = ic->wh_px[0].whole, h = ic->wh_px[1].whole, bs, fs, gap, lw,
	    rw, tl, x0, y0, pad, m, n;
	lws_html_w_t hw;

	/*
	 * The controls are as big as they comfortably can be to press, in the
	 * middle, away from the edges.  On a round display, they're smaller,
	 * to stay inside the circle
	 */

	bs = clamp(ic->round ? h / 11 : h / 9, 16, 56);
	fs = clamp((bs * 3) / 5, 10, 24);
	gap = bs / 4 > 2 ? bs / 4 : 2;
	tl = (fs * 6) / 5;
	pad = (bs - tl) / 2 > 0 ? (bs - tl) / 2 : 0;
	/* the edge's name, then -, how many px, + */
	lw = fs * 4;
	rw = lw + 3 * bs + 2 * gap;
	x0 = (w - rw) / 2 > 2 ? (w - rw) / 2 : 2;
	/* the edges' rows, the buttons' row, and two lines of text */
	y0 = (h - (5 * bs + 5 * gap + 2 * tl)) / 2;
	if (y0 < 2)
		y0 = 2;

	lws_html_w_init(&hw, buf, len);

	lws_html_w_printf(&hw, "<!doctype html><html><head>"
		"<meta charset=\"utf-8\"><style>"
		"* { margin: 0; padding: 0 }"
		"body { background-color: #fff; color: #000; font-family: sans;"
		" font-size: %dpx }"
		".k, .r, .n, .v, .x, a { position: absolute }"
		".k { background-color: #000 }"
		".r { left: %dpx; width: %dpx; height: %dpx }"
		".n { left: 0; top: %dpx; width: %dpx; height: %dpx }"
		".v, .x { text-align: center; white-space: nowrap;"
		" overflow: hidden }"
		".v { left: %dpx; top: %dpx; width: %dpx; height: %dpx }"
		"a { display: block; background-color: #000; color: #fff;"
		" text-decoration: none; text-align: center; top: 0;"
		" width: %dpx; height: %dpx; padding-top: %dpx }"
		".m { left: %dpx } .p { left: %dpx }"
		".x { left: 0; width: %dpx; height: %dpx }",
		fs, x0, rw, bs,
		pad, lw, tl,
		lw + bs + gap, pad, bs, tl,
		bs, bs - pad, pad,
		lw + gap, lw + 2 * (bs + gap),
		w, tl);

	/* the line around the edges of what can be seen */

	line(&hw, "et", 0, 0, w, 1);
	line(&hw, "eb", 0, h - 1, w, 1);
	line(&hw, "el", 0, 0, 1, h);
	line(&hw, "er", w - 1, 0, 1, h);

	/* the rows, the buttons, and the lines of text below them */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(edges) + 1; n++)
		lws_html_w_printf(&hw, "#r%d { top: %dpx }", n,
				  y0 + n * (bs + gap));
	lws_html_w_printf(&hw, "#ar { left: 0; width: %dpx }"
			       "#ad { left: %dpx; width: %dpx }"
			       "#x0 { top: %dpx } #x1 { top: %dpx }",
			       (rw - gap) / 2, (rw + gap) / 2, (rw - gap) / 2,
			       y0 + 5 * (bs + gap), y0 + 5 * (bs + gap) + tl);

	/* where the last touch landed, if it was on what can be seen */

	m = bs / 2;
	if (t->valid && t->inside) {
		line(&hw, "ch", clamp(t->vx - m, 0, w - 1), t->vy,
		     clamp(t->vx + m, 0, w - 1) - clamp(t->vx - m, 0, w - 1) + 1,
		     1);
		line(&hw, "cv", t->vx, clamp(t->vy - m, 0, h - 1), 1,
		     clamp(t->vy + m, 0, h - 1) - clamp(t->vy - m, 0, h - 1) + 1);
	}

	lws_html_w_printf(&hw, "</style></head><body>"
		"<div class=\"k\" id=\"et\"></div>"
		"<div class=\"k\" id=\"eb\"></div>"
		"<div class=\"k\" id=\"el\"></div>"
		"<div class=\"k\" id=\"er\"></div>");

	for (n = 0; n < (int)LWS_ARRAY_SIZE(edges); n++)
		lws_html_w_printf(&hw, "<div class=\"r\" id=\"r%d\">"
			"<div class=\"n\">%s</div>"
			"<a class=\"m\" href=\"?%c-\">-</a>"
			"<div class=\"v\">%d</div>"
			"<a class=\"p\" href=\"?%c+\">+</a></div>",
			n, edges[n].name, edges[n].c, inset[edges[n].idx],
			edges[n].c);

	lws_html_w_printf(&hw, "<div class=\"r\" id=\"r4\">"
		"<a id=\"ar\" href=\"?reset\">Reset</a>"
		"<a id=\"ad\" href=\"?done\">Done</a></div>"
		"<div class=\"x\" id=\"x0\">Seen: %d x %d</div>"
		"<div class=\"x\" id=\"x1\">", w, h);

	if (!t->valid)
		lws_html_w_printf(&hw, "Touch to see where it lands");
	else if (t->inside)
		lws_html_w_printf(&hw, "Touch: %d, %d (surface %d, %d)",
				  t->vx, t->vy, t->sx, t->sy);
	else
		lws_html_w_printf(&hw, "Touch: in the inset (surface %d, %d)",
				  t->sx, t->sy);

	lws_html_w_printf(&hw, "</div>");

	if (t->valid && t->inside)
		lws_html_w_printf(&hw, "<div class=\"k\" id=\"ch\"></div>"
				       "<div class=\"k\" id=\"cv\"></div>");

	lws_html_w_printf(&hw, "</body></html>");

	return lws_html_w_len(&hw, buf);
}

lhp_edges_act_t
lhp_edges_href(const char *href, uint8_t inset[4])
{
	size_t n;

	if (!strcmp(href, "?reset"))
		return LHP_EDGES_ACT_RESET;
	if (!strcmp(href, "?done"))
		return LHP_EDGES_ACT_DONE;

	/* the edges' controls are ?<edge><- or +> */

	if (href[0] != '?' || !href[1] || (href[2] != '-' && href[2] != '+') ||
	    href[3])
		return LHP_EDGES_ACT_NONE;

	for (n = 0; n < LWS_ARRAY_SIZE(edges); n++) {
		uint8_t *v = &inset[edges[n].idx];

		if (href[1] != edges[n].c)
			continue;

		if (href[2] == '-') {
			if (!*v)
				return LHP_EDGES_ACT_NONE;
			(*v)--;
		} else {
			if (*v >= LHP_EDGES_MAX)
				return LHP_EDGES_ACT_NONE;
			(*v)++;
		}

		return LHP_EDGES_ACT_CHANGED;
	}

	return LHP_EDGES_ACT_NONE;
}

static lws_settings_instance_t *
settings(struct lws_context *cx)
{
	lws_netdevs_t *nds = lws_netdevs_from_ctx(cx);

	return nds ? nds->si : NULL;
}

int
lhp_edges_load(struct lws_context *cx, uint8_t inset[4])
{
	lws_settings_instance_t *si = settings(cx);
	uint8_t s[4];
	size_t l = sizeof(s);
	int n;

	if (!si || si->so->get(si, EDGES_SETTING, s, &l) || l != sizeof(s))
		return 1;

	/* what is stored is untrusted until we see it is an inset we'd store */
	for (n = 0; n < 4; n++)
		if (s[n] > LHP_EDGES_MAX)
			return 1;

	memcpy(inset, s, sizeof(s));

	return 0;
}

int
lhp_edges_store(struct lws_context *cx, const uint8_t inset[4])
{
	lws_settings_instance_t *si = settings(cx);

	return !si || si->so->set(si, EDGES_SETTING, inset, 4);
}
