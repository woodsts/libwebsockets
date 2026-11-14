/*
 * lws-api-test-display-inset
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests a display's inset, the px at its edges that can't be seen, eg, under
 * a bezel or a touch panel's mask.  Against a pretend display that keeps
 * what it's blitted, it checks
 *
 *  - the display state's surface, what to lay out and draw on, is the part
 *    inside the inset, with its size in mm what that part is
 *
 *  - an update drawn on that, blitted with lws_display_blit(), reaches the
 *    display as lines of its whole surface where they belong, with the inset
 *    at their sides white
 *
 *  - a point on the surface, eg, a touch, is where it is on what can be
 *    seen, and one in the inset is said to be outside it
 *
 *  - rows in the inset that may show something from before, eg, it was just
 *    made bigger, are made white by the next update reaching them, then
 *    left alone, including when the update comes in bands
 *
 *  - an inset leaving nothing to see is refused
 *
 *  - with no inset, what's blitted goes straight to the display
 */

#include <libwebsockets.h>
#include <string.h>

#define W	20
#define H	10

static int fail;
/* the pretend display's surface, Y */
static uint8_t fb[H][W];
static int starts, ends, lines;
static lws_box_t start_box;
static const uint8_t *last_src;

#define check(_c, ...) do { if (!(_c)) { \
		lwsl_err("%s:%d: %s\n", __func__, __LINE__, #_c); \
		lwsl_err(__VA_ARGS__); fail = 1; } } while (0)

static int
pretend_init(lws_display_state_t *lds)
{
	(void)lds;

	return 0;
}

static int
pretend_blit(lws_display_state_t *lds, const uint8_t *src, lws_box_t *box,
	     lws_dll2_owner_t *ids)
{
	(void)lds;
	(void)ids;

	switch (box->h.whole) {
	case 0:
		ends++;
		break;
	case 1:
		check(box->x.whole == 0 && box->w.whole == W,
		      "line %d,%d w %d, not all the surface\n",
		      (int)box->x.whole, (int)box->y.whole,
		      (int)box->w.whole);
		check(box->y.whole >= 0 && box->y.whole < H,
		      "line %d off the surface\n", (int)box->y.whole);
		if (box->y.whole >= 0 && box->y.whole < H) {
			if (src)
				memcpy(fb[box->y.whole], src, W);
			else
				memset(fb[box->y.whole], 0xff, W);
		}
		last_src = src;
		lines++;
		break;
	default:
		starts++;
		start_box = *box;
		break;
	}

	return 0;
}

static const lws_display_t disp = {
	.init			= pretend_init,
	.blit			= pretend_blit,
	.name			= "pretend",
	.ic = {
		.wh_px		= { { W, 0 }, { H, 0 } },
		.wh_mm		= { { 40, 0 }, { 20, 0 } },
		.type		= LWSSURF_PALETTE,
		.greyscale	= 1,
	},
	/* left, top, right, bottom */
	.inset			= { 2, 1, 3, 2 },
};

/* an update of rows y0 up to y1 of what can be seen, black */

static void
draw_band(lws_display_state_t *lds, int y0, int y1)
{
	uint8_t line[W];
	lws_box_t box;
	int y;

	memset(line, 0, sizeof(line));
	memset(&box, 0, sizeof(box));
	box.w = lds->ic.wh_px[0];
	box.y.whole = y0;
	box.h.whole = y1 - y0;
	lws_display_blit(lds, (uint8_t *)lds, &box, NULL);

	box.h.whole = 1;
	for (y = y0; y < y1; y++) {
		box.y.whole = y;
		lws_display_blit(lds, line, &box, NULL);
	}

	box.h.whole = 0;
	lws_display_blit(lds, NULL, &box, NULL);
}

/* an update of all of what can be seen, black */

static void
draw_black(lws_display_state_t *lds)
{
	draw_band(lds, 0, lds->ic.wh_px[1].whole);
}

/*
 * How many px of the pretend display aren't what an update of all of what can
 * be seen, black, inside the inset l, t, r, b leaves: rows in the inset are
 * white if they were made white, or the 0x80 they were set to before
 */

static int
check_fb(int l, int t, int r, int b, int rows_whitened)
{
	int x, y, bad = 0, in;
	uint8_t want;

	for (y = 0; y < H; y++)
		for (x = 0; x < W; x++) {
			in = x >= l && x < W - r && y >= t && y < H - b;
			if (y < t || y >= H - b)
				want = rows_whitened ? 0xff : 0x80;
			else
				want = in ? 0 : 0xff;
			if (fb[y][x] != want)
				bad++;
		}

	return bad;
}

static void
counts_reset(void)
{
	starts = ends = lines = 0;
	memset(fb, 0x80, sizeof(fb));
}

static void
test_inset(struct lws_context *cx)
{
	static const uint8_t nothing[4] = { 10, 0, 10, 0 };
	lws_display_state_t lds;
	int x, y, bad;

	lws_display_state_init(&lds, cx, -1, -1, NULL, &disp);

	/* what to lay out on is what's inside the inset */

	check(lds.ic.wh_px[0].whole == W - 5 && lds.ic.wh_px[1].whole == H - 3,
	      "visible %d x %d\n", (int)lds.ic.wh_px[0].whole,
	      (int)lds.ic.wh_px[1].whole);
	/* 15 / 20 of 40mm, 7 / 10 of 20mm */
	check(lds.ic.wh_mm[0].whole == 30 && lds.ic.wh_mm[1].whole == 14,
	      "visible %d x %d mm\n", (int)lds.ic.wh_mm[0].whole,
	      (int)lds.ic.wh_mm[1].whole);

	/*
	 * Drawn on that, it lands inside the inset, which is white.  What the
	 * display showed in the rows of the inset before is unknown, so the
	 * first update makes them white too, widened to all of the surface
	 */

	counts_reset();
	draw_black(&lds);

	check(starts == 1 && ends == 1 && lines == H,
	      "%d starts, %d ends, %d lines\n", starts, ends, lines);
	check(start_box.x.whole == 0 && start_box.y.whole == 0 &&
	      start_box.w.whole == W && start_box.h.whole == H,
	      "start box %d,%d %dx%d\n", (int)start_box.x.whole,
	      (int)start_box.y.whole, (int)start_box.w.whole,
	      (int)start_box.h.whole);
	bad = check_fb(2, 1, 3, 2, 1);
	check(!bad, "first: %d px wrong\n", bad);

	/* after that, the rows in the inset are left alone */

	counts_reset();
	draw_black(&lds);

	check(starts == 1 && ends == 1 && lines == H - 3,
	      "%d starts, %d ends, %d lines\n", starts, ends, lines);
	check(start_box.x.whole == 0 && start_box.y.whole == 1 &&
	      start_box.w.whole == W && start_box.h.whole == H - 3,
	      "start box %d,%d %dx%d\n", (int)start_box.x.whole,
	      (int)start_box.y.whole, (int)start_box.w.whole,
	      (int)start_box.h.whole);
	bad = check_fb(2, 1, 3, 2, 0);
	check(!bad, "second: %d px wrong\n", bad);

	/* a touch on the surface is where it is on what can be seen */

	x = 2;
	y = 1;
	check(!lws_display_visible_xy(&lds, &x, &y) && !x && !y,
	      "top left %d,%d\n", x, y);
	x = W - 4;
	y = H - 3;
	check(!lws_display_visible_xy(&lds, &x, &y) && x == W - 6 && y == H - 4,
	      "bottom right %d,%d\n", x, y);
	x = 1;
	y = 5;
	check(lws_display_visible_xy(&lds, &x, &y), "left inset visible\n");
	x = 5;
	y = H - 2;
	check(lws_display_visible_xy(&lds, &x, &y), "bottom inset visible\n");

	/* an inset with nothing inside it is refused, and changes nothing */

	check(lws_display_set_inset(&lds, nothing), "nothing to see allowed\n");
	check(lds.ic.wh_px[0].whole == W - 5 && lds.inset[0] == 2,
	      "refused inset changed it\n");
	check(!lds.inset_stale, "refused inset made rows stale\n");

	lws_display_state_fini(&lds);
	check(!lds.inset_line, "line not freed\n");
}

/*
 * The inset is changed, eg, while finding out what it should be: rows that
 * were drawn on before are in it now, and must be made white
 */

static void
test_inset_change(struct lws_context *cx)
{
	static const uint8_t bigger[4] = { 2, 3, 3, 1 };
	lws_display_state_t lds;
	int bad;

	lws_display_state_init(&lds, cx, -1, -1, NULL, &disp);
	draw_black(&lds);

	check(!lws_display_set_inset(&lds, bigger), "bigger refused\n");
	check(lds.ic.wh_px[1].whole == H - 4, "visible h %d\n",
	      (int)lds.ic.wh_px[1].whole);

	/*
	 * Updated in two bands: the top rows of the inset go with the band at
	 * the top of what can be seen, the bottom with the one at its bottom,
	 * each still lines all together
	 */

	counts_reset();
	draw_band(&lds, 0, 2);
	check(starts == 1 && lines == 3 + 2 && start_box.y.whole == 0 &&
	      start_box.h.whole == 3 + 2, "top band: %d lines, box y %d h %d\n",
	      lines, (int)start_box.y.whole, (int)start_box.h.whole);
	draw_band(&lds, 2, H - 4);
	check(starts == 2 && lines == H && start_box.y.whole == 3 + 2 &&
	      start_box.h.whole == H - 4 - 2 + 1,
	      "bottom band: %d lines, box y %d h %d\n", lines,
	      (int)start_box.y.whole, (int)start_box.h.whole);
	bad = check_fb(2, 3, 3, 1, 1);
	check(!bad, "changed: %d px wrong\n", bad);
	check(!lds.inset_stale, "still stale\n");

	/* a band in the middle leaves the stale rows for one that reaches them */

	check(!lws_display_set_inset(&lds, disp.inset), "back refused\n");
	counts_reset();
	draw_band(&lds, 2, 4);
	check(lines == 2 && start_box.y.whole == 1 + 2 &&
	      start_box.h.whole == 2, "middle band: %d lines, box y %d h %d\n",
	      lines, (int)start_box.y.whole, (int)start_box.h.whole);
	check(lds.inset_stale == (LWS_DISPLAY_INSET_STALE_TOP |
				  LWS_DISPLAY_INSET_STALE_BOTTOM),
	      "stale %d\n", lds.inset_stale);

	lws_display_state_fini(&lds);
}

static void
test_no_inset(struct lws_context *cx)
{
	static const uint8_t none[4];
	lws_display_state_t lds;
	uint8_t line[W];
	lws_box_t box;

	lws_display_state_init(&lds, cx, -1, -1, NULL, &disp);
	check(!lws_display_set_inset(&lds, none), "no inset refused\n");
	check(lds.ic.wh_px[0].whole == W && lds.ic.wh_px[1].whole == H,
	      "visible %d x %d\n", (int)lds.ic.wh_px[0].whole,
	      (int)lds.ic.wh_px[1].whole);

	/* lines go to the display as they are */

	memset(line, 0, sizeof(line));
	memset(&box, 0, sizeof(box));
	box.w.whole = W;
	box.h.whole = 1;
	box.y.whole = 3;
	lws_display_blit(&lds, line, &box, NULL);
	check(last_src == line, "line not passed on as it was\n");

	lws_display_state_fini(&lds);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *cx;

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS API Test - display inset\n");

	info.port = CONTEXT_PORT_NO_LISTEN;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("context creation failed\n");
		return 1;
	}

	test_inset(cx);
	test_inset_change(cx);
	test_no_inset(cx);

	lws_context_destroy(cx);

	lwsl_user("Completed: %s\n", fail ? "FAIL" : "PASS");

	return fail;
}
