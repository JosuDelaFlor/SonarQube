<?php
function biderketa($x, $y) {
    $emaitza = $x * $y;

    // BUG & Code Smell: Erabili gabeko aldagaia
    $erabiliGabe = 123;

    return $x * $y;
}
