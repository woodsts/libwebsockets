/*
 * lhp edges and touch page
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A page for finding out the display's inset, the px at its edges that can't
 * be seen, eg, under a bezel or a touch panel's mask (see lws_display_t
 * .inset), and for seeing if touches land where they are on the display.
 *
 * It's a 1px black line around the edges of what can be seen, inside the
 * inset in use, with a row of controls for each edge: - and + make the inset
 * there a px smaller or bigger, moving the line out or in, with how many px
 * it is between them.  The inset is right when the line is just seen all the
 * way round.  Below them, the size of what can be seen, and where the last
 * touch that wasn't on a control landed, which is also marked with a cross:
 * if the cross isn't under where it was touched, it's the touch panel that's
 * not where the display is.
 *
 * The inset found is stored in the settings, and used from then on instead of
 * the board's, see lhp_edges_load().
 */

#if !defined(__LHP_EDGES_UI_H__)
#define __LHP_EDGES_UI_H__

#include <libwebsockets.h>

/* the biggest inset at any edge the page goes to */
#define LHP_EDGES_MAX		64

/* the most the page's html can be */
#define LHP_EDGES_HTML_MAX	4096

/* where a touch landed */

typedef struct lhp_edges_touch {
	int		sx, sy;		/* on the display's surface */
	int		vx, vy;		/* on what can be seen, if .inside */
	uint8_t		valid;		/* there was one */
	uint8_t		inside;		/* it was on what can be seen */
} lhp_edges_touch_t;

typedef enum {
	LHP_EDGES_ACT_NONE,
	LHP_EDGES_ACT_CHANGED,		/* the inset was changed */
	LHP_EDGES_ACT_RESET,		/* go back to the board's inset */
	LHP_EDGES_ACT_DONE,		/* finished with the page */
} lhp_edges_act_t;

/**
 * lhp_edges_html() - write the page's html
 *
 * \param buf: where to write it
 * \param len: its size
 * \param ic: what can be seen of the display, lws_display_state_t .ic
 * \param inset: the inset in use, left, top, right, bottom
 * \param t: where the last touch landed
 *
 * Returns the length of the html, or -1 if it didn't fit.
 */
int
lhp_edges_html(char *buf, size_t len, const lws_surface_info_t *ic,
	       const uint8_t inset[4], const lhp_edges_touch_t *t);

/**
 * lhp_edges_href() - a link on the page was pressed
 *
 * \param href: its href, as written
 * \param inset: the inset in use, changed if it's one of the edges' controls
 *
 * Returns what it asks for.  LHP_EDGES_ACT_CHANGED is only returned if the
 * inset was changed, eg, not a - at an edge that's already 0.
 */
lhp_edges_act_t
lhp_edges_href(const char *href, uint8_t inset[4]);

/**
 * lhp_edges_load() - the inset stored in the settings, if any
 *
 * \param cx: the lws context, whose netdevs have the settings
 * \param inset: set to the stored inset
 *
 * Returns 0 if one was stored, or nonzero if not, or it isn't one we could
 * have stored.
 */
int
lhp_edges_load(struct lws_context *cx, uint8_t inset[4]);

/* store the inset in the settings, returning nonzero if it couldn't be */
int
lhp_edges_store(struct lws_context *cx, const uint8_t inset[4]);

#endif
