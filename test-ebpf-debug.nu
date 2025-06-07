# Debug: check if closure syntax works
def test [] {
    echo "Testing closure syntax"
    let c = {|| echo "test" }
    do $c
}

test