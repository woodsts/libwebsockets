# lws api test display inset

Tests a display's inset, `lws_display_t .inset`, the px at the edges of its
surface that can't be seen, eg, under a bezel or the mask of a touch panel
over it, against a pretend display that keeps what it's blitted.

It checks

 - the display state's `.ic`, what to lay out and draw on, is the part of
   the surface inside the inset, with its size in mm what that part is

 - an update drawn on that and blitted with `lws_display_blit()` reaches the
   display as lines of its whole surface where they belong, with the inset at
   their sides white, and the rows in the inset not blitted

 - `lws_display_visible_xy()` gives where a point on the surface, eg, a
   touch, is on what can be seen, and says when it's in the inset

 - `lws_display_set_inset()` refuses an inset leaving nothing to see

 - with no inset, lines are passed to the display as they are

## build

```
 $ cmake .. -DLWS_WITH_DRIVERS=1 -DLWS_WITH_MINIMAL_EXAMPLES=1 && make
```

## usage

```
 $ ./bin/lws-api-test-display-inset
[2026/11/14 14:30:00:0000] U: LWS API Test - display inset
[2026/11/14 14:30:00:0001] U: Completed: PASS
```
