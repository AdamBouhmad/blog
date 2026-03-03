+++
author = "Adam Bouhmad"
title = "Rust Study Notes"
description = "Rust Study Notes"
date = "2026-03-02"
categories = ["Rust", "Development", "Systems Programming"]
tags = ["rust", "development"]
menu = "main"
featured = ""
featuredalt = ""
featuredpath = ""
linktitle = ""
type = "post"
draft = true
+++

## Chapter 1

Compiler in rust refuses to compile code with low-level code bugs, such as concurrency bugs,
making it easier for devs to get shit done vs undergoing extensive testing & code review
- Cargo is the dependency manager & build tool – easy to manage deps, compile & build code
- Rustfmt is a formatting tool used to make sure styling is consistent across codebases
- Rust Lanaguage Server helps as an IDE integration for inline error msgs while coding
Usecases:
- Devops Tooling
- Web Services
- CLI tools
- Embedded device software
- bio informatics
- Search Engines
- IoT apps
- ML
- Major parts of Firefox Web Browser
Eliminates the trade-offs between safety & productivity, speed & ergonomics. Meant to be fast to
get started, and fast to run
New files should use underscores to separate words vs being lumped together
Rustfmt is cool af, great to use in working dirs after you've coded to make sure styling is in
synch with standards. Maybe a pre-commit hook that gets ran:
https://github.com/rust-lang/rustfmt
Ahead of time compiled language – meaning you can compile a program and ive the exe to
someone else, and they can run it w/o rust being installed
Cargo is great because it handles alot of tasks like building code, downloading libraries our
code depends on, and building those libraries. You can use cargo to create new directory for
your project, using cargo new <project_name>. A cargo.toml(tom's obvious, minimal language)
config file is created, along with a src dir that includes your default main.rs file with a basic hello
world code snippet

```rust
fn main () {
println!("Hello World!")
}
```

The main fun is the entrypoint for your code
Packages/Libraries in Rust are called crates. Dependencies are defined in your config.toml file.

```text
cargo new <project_name>
cargo build
cargo check
cargo run
cargo build --release
```

## Chapter 2

Variables in rust by default are immutable. Yes, the values are immutable(not the types). What
does this mean? Well, if mut is not declared before the variable name, the value can not
change. This is a functional choice to ensure devs are thinking about which variables should be
mutable and why.
- When variables are immutable, it makes it easier to understand & reason about your
code, reducing potential bugs(or narrowing down where they may be)
- Immutable data can be shared safely between threads without needing complex
synchronization; reducing the risk of data races which is apparently a common source of
bugs in concurrent programming
- Immutable data allows the compiler to make optimizations with the guarantee that the
value won't change, making for more efficiently compiled code.
Variables are declared using the let keyword.
i.e:
let first_name = "Adam"
Or for a mutable value that you believe will change(i.e I could legally change my first name):
let mut first_name = "Adam"
& indicates the argument is a reference, which gives you a way to let multiple parts of your code
access a piece of dt w/o needing to copy the same data into memory multiple times.
References are immutable by default. Use &mut <varname> rather than &<varname> to make
the reference mutable.
read_lines func in the std library puts user input into a variable we're passing to it, but also
returns an enum called Result. An ENUM is a type that can be in multiple states(also called a
variant). A great example of an enum would be a day of the week, with each state being a
number representing a day of the week(1-7).
Result has two states, Ok and Err based on whether or not the operation succeeded.
expect func in the std library allows you to error handle unexpected values in your user input,
and display and error message back to the user upon crash. You will get a warning at compile
time if you do not write error handling code for expect, as rust recommends you error handle
appropriately versus just crash.
{} curly braces serves as a placeholder for variable names(and referencing their values) when
youre printing them. Very different than python, as you can reference a var directly in a print like
so without having to concatenate the value with a string:

```rust
println!("My name is {first_name}!")
```

My name is Adam!
Want to evaluate expressions on the fly? Follow an empty curly bracket placeholder with your
values being evaluated:

```rust
let x = 10;
let y = 2;
println!("x = {x} and y + 2 = {}", y + 2);
```

There is no std library pkg for random number generation yet
Provided via a crate however
Add it like so to your cargo.toml file:

```toml
[dependencies]
rand = "0.8.5"
```

Rust understands semantic versioning. However, 0.8.5 means any version greater than 0.8.5
but less than 0.9.0. To pin, you must: use an equals sign:

```toml
[dependencies]
rand = "=0.8.5"
```

crates.io is where folks post their open source rust projs for others to use
Cargo fetches latest deps from a registry, which is a copy of the data in crates.io
Cargo lock file is important, as it's all of the pinned deps used to build your project successfully,
allowing you to have a reproducible build. Very helpful in the case versions change in ur deps
file(i.e you specified deps that werent pinned using =). Lock file is typically checked into source
control.
Cargo update will ignore the lock file and find the latest versions of the dependencies specified
in your config file. Cargo will then write the versions to the lock file.
Generate docs for all locally installed created by running via the CLI:

```text
cargo doc --open
```

REMEMBER, YOU WILL NOT KNOW WHAT TRAITS & METHODS, FUNCTIONS TO CALL
FROM A CRATE UNLESS YOU RTFM! DONT HAVE IMPOSTER SYNDROME, JUST READ!
Rust has type inference, in the case you do not want to define the variable type it will infer it
based on the data passed. Rust also has the notion of Shadowing, letting you reuse variable
names rather than forcing the creation of two unique variables(i.e guess_str & guess_int).
Need to understand Chapter 2 pg 25, how shadowing works and the difference in the types i32
& u32

```rust
let mut guess = String::new();
let guess: i32 = guess
    .trim()
    .parse()
    .expect("Guess must be a number!");
```

Colon after variable name means we're going to annotate the type, i.e let guess: string = guess
- Relevant for shadow variables
.trim() will remove whitespace and remove newlines, etc from values received
Parse converts input to nums. It must logically make sense(i.e a UTF-8 unicode set of chars,
like an emoji, can not become a num)
In rust, an underscore is a catchall value(wildcard)
i.e

```rust
Ok(num) => num,
Err(_) => continue,
```

Means any value passed to the guess variable that is not a signed 32bit integer will result in an
error state, but the program will continue.

## Chapter 3

Constants, always immutable, never changing. When defining, their names should be all caps
with underscores between words.

```rust
const HOURS_IN_A_DAY: i32 = 24;
```

Constants must be explicitly defined at compile time.
For Variables, although declared immutable with let, these variables are assigned values at
runtime. Their immutability means you cannot change their value after assignment, but the
value itself isn't necessarily known until the program runs.
Can't mutate a variables type, but you can mutate it's values
However, you can shadow a variable, and do actions on that variable
Example:

```rust
let number = 5
let number = number + 5
println!("{number}")
```

The value is 10
This basically helps so that way you don't have to create additional variables, but can be a bit
tricky to remember as it's counter to how other languages handle variables
Statically typed language – meaning the compiler must know the data type of all variables at
compile time
Scalar types hold single values. Complex numbers, and strings are not scalars, however in rust
integers, floating-point numbers, Booleans, and characters are scalar types.
Signed and unsigned refer to whether it's possible for the number to be negative(whether the
number needs to have a sign with it, or whether it's positive and doesnt need a sign)
- Each signed variant can store numbers from -(2^n - 1) to 2^n - 1 - 1
  - Example, i32 would be:
    - -(2^31) -> (2^31) -1

Length Signed Unsigned
8-bit i8 u8
16-bit i16 u16
32-bit i32 u32
64-bit i64 u64
128-bit i128 u128
arch isize usize

Rust's two complement wrapping is interesting; it's how you prevent integer overflow when
compiling with release flags(the compiler will panic and error at runtime during debug mode
when youre developing).
Essentially, if you have something like an u8 integer, and you provide it the value 257, the
integers value will "wrap around". The 256 value will be represented as 0, and 257 will be
represented as a 1.
Keep in mind u8 will store up to 255. i8 will store between -128 - 127
Conditional logic example:

```rust
if energy >= 7 {
    is_satisfied = true;
}
else {
    is_satisfied = false;
}
```

Returning values works the same as it does anywhere else. Here's an example of defining a
new function that will return a boolean:

```rust
fn boolean_test() -> bool {
    let mut is_satisfied: bool = true;
    let mut energy: i64 = 10;
    energy = 2;
    if energy >= 7 {
        is_satisfied = true;
    }
    else {
        is_satisfied = false;
    }
    return is_satisfied;
}
```

Referencing the function and printing out its value in main works like so:

```rust
fn main() {
    println!("{}", boolean_test());
}
```

Chars are unicode scalar characters, similar to UTF-8 encoded text(think if you want emojis in
your app, i.e D7FF)
- Delimited by single quotes, not double, as opposed to strings.
Compound types can group multiple vals into a single type. In rust, there's just tuples & arrays
In rust, the last expression in a function is implicitly returned, but when you add a semicolon,
rust discards the value unless you have an explicit return statement.
ALSO, TIL static str?

```rust
fn tupletest() -> &'static str {
    let person = ("Adam", "adbouhmad@gmail.com", 28);
    let (name, _email, _age) = person;
    name
}
```

Instead of doing the destructuring to break a tuple into multiple parts, you could just reference it
based on
Arrays are fixed, vectors grow or shrink in size depending; if youre unsure of which to use, use a
vector.
Rust uses snakecase for function and variable names
(another_function()); <- example
Parameters(or arguments) are special variables that are part of a functions signature
Example func definition in rust w/arguments:

```rust
fn main( ){
    birthday_year("May", 12, 1996);
}
fn birthday_year(month: &str, day: i32, year: i32){
    println!("I was born on {month} {day}, {year}");
}
```

Prints: I was born on May 12, 1996
TODO: Talk about &str vs Strings & their impact on memory allocation vs borrowing
You must declare the type of each param; requiring type annotations means the compiler doesnt
need to use them elsewhere in the code to figure out what the type is, and the compiler can give
you more helpful error msgs.
Functions are made up of statements, optionally ending in an expression
A statement performs an action, but doesnt return a value (i.e let x: i8 = 127;)
Expressions evaluate to a resultant value(i.e calling a function is an expression)
Keep in mind that expressions do not include ending semicolons

## Chpt 4

With string literals, they are immutable, so they are fast and efficient, we know what the values
will be at compile time and we utilize the stack
With the String type, they can be mutable, and could be a growable piece of text(think user input
as a text field), so we must allocate memory onto the heap; memory is requested by the
memory allocator at runtime, and we need a way to return the memory to the allocator when
we're done with the string
- First part is done by us by calling String::from – memory is requested(universal across
languages)
- Second part is handled by GC(garbage collector) – cleans up mem thats not being used
anymore.
  - In languages w/o GC, you handle it yourself; do it too early, you have an invalid
variable, forget it you waste memory, do it twice, its a bug, one alloc(or malloc for
heap) needs to be paired with one free
  - In Rust its different, mem is automatically returned once the var that owns the
mem goes out of scope.
    - When a variable goes out of scope, Rust calls a function called drop
automatically at the closing curly bracket. This pattern of dealloc
resources at the end of an items lifetime is also called Resource
Acquisition Is Initialization(RAII).
Capacity is the total amount of mem in bytes that a variable(i.e a String) has received from the
allocator. The Length is how much mem, in bytes, the contents of a variable are currently using.

```rust
let name = String::from("adam")
let first_name = name;
```

In the example above, first_name does not get a copy of the value in name, instead first_name
stores the pointer, length, and capacity that are on the stack. This is done to save memory in
terms of runtime performance incase data on the heap were especially large
With let x = 5; let y = x; the values are effectively copied – these are fixed, known, simple
values. It doesnt matter if x is mutable, y gets its own separate copy of the value 5 in memory
(on the stack), independent of x.
INTERESTING SECURITY TIDBIT:
Double free Error – when a dev or GC accidentally try to free memory twice, leading to memory
corruption which could lead to sec vulns. This could happen with the following scenario:

```rust
Let s1 = String::from("hello");
Let s2 = s1;
```

If Rust were not memory safe, when the vars are out of scope and dropped, s1 would free
memory at it's pointer in the stack, and then s2 would also attempt to free memory at the pointer
in the stack specified by s1. Luckily Rust considers s1 as no longer valid after s2 declares itself
as equal to s1, so rust doesnt need to free anything when s1 goes out of scope; s1's value is
effectively borrowed by s2

```rust
fn main() {
 let name = string_func();
 println!("{}", name);
}
fn string_func() -> String {
 let mut name = String::from("Adam");
 // name.push_str(" Bouhmad. He doesn't have a middle name");
 // name.pop();
 let name2 = name;
 return name;
}
```

```text
error[E0382]: use of moved value: `name`
--> src/main.rs:19:12
|
11 | let mut name = String::from("Adam");
| -------- move occurs because `name` has type `String`, which does not implement the `Copy` trait
...
17 | let name2 = name;
| ---- value moved here
18 |
19 | return name;
| ^^^^ value used here after move
```

This is different from other languages "shallow copy" or "deep copy", as rust not only copies the
pointer, length, and capacity without copying the data, but also invalidates the first variable. For
that reason, this is called a move. In the above, name is moved to name2. The design decision
rust made here is that Rust will never automatically create "deep" copies of data, so automatic
copies are inexpensive in terms of runtime performance.

```rust
fn string_func() -> String {
 let mut name = String::from("Adam");
 // name.push_str(" Bouhmad. He doesn't have a middle name");
 // name.pop();
 let name2 = name.clone();
 return name;
}
```

If we do want to deeply copy the data, we can use the 'clone' method. Because the heap data is
copied in this scenario, arbitrary code is being executed and the code may be expensive.
You can actually just print a variable by putting the var name in the brackets when printing,
versus having to use a comma. Helpful for when you have multiple vars you want to print:

```rust
println!("{name2}");
```

Rust has a special Copy trait thats placed onto types, like ints, that are stored on the stack. With
the Copy trait, variables that use it do not move, but rather are copied, making them still valid
after assignment to another variable. Scope limits apply if the var has been dropped :)
You can add the Copy annotation to a type to implement the trait, but by default can implement
simple scalar values but the following cannot:
- Nothing that required mem allocation
- resources(?)
Types that implement Copy Trait
- All INT types such as u32
- Boolean type(bool)
- All FLOATS, such as f64
- Character type CHAR
- Tuples if they only that contain types that implement Copy
  - I.e (i32, u32), but not (i32, String)
Ooh this is an interesting one: Passing a variable to a func will move or copy in the same ways
assignment works

```rust
fn main() {
 let first_name = String::from("Adam");
 my_name(first_name);
 println!("{first_name}"); // this wont work, as function my_name takes ownership over var first_name
 make_copy(5);
}
fn my_name(name: String){
 println!("My name is {name}");
} //freed after this point
fn make_copy(some_integer: i32) {
 println!("The special number is {some_integer}");
}
```

```text
error[E0382]: borrow of moved value: `first_name`
--> src/main.rs:11:15
```

Three forward slashes documents your comment in the rustlang docs. You can open the docs
by typing:

```text
cargo doc --open
```

To check if a number is divisible by another number, you can use the modulo operator
Modulo definition: (in number theory) with respect to or using a modulus of a specified number.
Two numbers are congruent modulo a given number if they give the same remainder when
divided by that number.

```rust
fn magic_number(n: u32) -> u32 {
 if n % 2 == 0{
 return 12;
 }
 else if n % 3 == 0 {
 return 13;
 }
 else{
 return 17;
 }
}
```

OK this is a gnarly one, and a great lesson about the stack:

```rust
fn main() {
 println!("Hello, world!");
 factorial(5);
}
fn factorial(n: u32) -> u32 {
 println!("Calling factorial({n})");
 let mut num: u32 = 0;
 if n == 0 {
 1
 } else {
 println!("{num}");
 num = (n * factorial(n - 1));
 println!("{}", num);
 return num;
 }
}
```

Imagine 5 is the number passed as an argument into our factorial function
In our loop, we're exiting and returning 1 once n = 0. Otherwise, we're iteratively recalling out
factorial function subtracting it by one, and multiplying by n. All of these transactions are stored
on the stack(remember first in, last out!). Eventually, the numbers are multiplied and our num is
returned.
Essentially num becomes 1 * 1 * 2 * 3 *4 * 5, and the value becomes stored as num.

```text
Hello, world!
Calling factorial(5)
0
Calling factorial(4)
0
Calling factorial(3)
0
Calling factorial(2)
0
Calling factorial(1)
0
Calling factorial(0)
1
2
6
24
120
```

Very weird, but cool to see recursion work in practice.
Chatgpt's amendment:
Base Case (Exit Condition)
- When n == 0, the function stops calling itself and returns 1.
- This is the first value returned when the recursion starts unwinding.
Recursive Calls (Building Up the Call Stack)
- If n > 0, the function calls itself with n - 1 before performing multiplication.
- These function calls are stored on the stack in a first in, last out (FILO) order.
Unwinding the Stack (Multiplication Happens Here!)
- Once factorial(0) returns 1, the function starts returning values up the stack.
- Each return value is multiplied by n, one step at a time, until we reach the original
function call.
Final Computation (How Multiplication Works)
The stack unwinds in reverse order, multiplying as follows:

```text
1 * 1 = 1
2 * 1 = 2
3 * 2 = 6
4 * 6 = 24
5 * 24 = 120
```

The todo!() macro is a placeholder that tells the compiler to ignore type errors. At run time it
panics
- Great for development to denmark something that needs to be finished, not used in prod
of course!
A profile is a definition for how your rust code will compile. Custom profiles can be created within
cargo.toml, otherwise, there are custom profiles, like dev release test & bench.
By default, running cargo build will build your rust code using the dev profile. To get your
optimizations, youll want to build using release. You can do so by typing cargo run --release.
Setting overflow-checks to false in cargo.toml ensures that values wrap around when they
overflow at runtime.
You can use saturating function (i.e i.saturating_mul(result)) to, when faced with an overflow,
have the value be the maximum value.
On the flipside, you can use the wrapping function (i.e i.wrapping_add(result)) to, when faced
with an overflow, have the value be the maximum value.
Struct data type allows you to define a type that stores a variety of different information. Think of
an example like

```rust
struct Person {
first_name: String,
last_name: String,
passion: String,
salary: i32
}
```

You can also define methods within your struct like so:

```rust
struct Person {
first_name: String,
last_name: String,
passion: String,
salary: i32
}
impl Person {
fn first_name(self) -> bool {
if first_name == "Adam"{
return true;
}
else {
return false;
}
}
}
```

You can then call this method like so:

```rust
let first_interviewee = Person {
first_name: "Adam",
last_name: "Bouhmad",
passion: "Building products that make a dent in the world and leave us better off",
salary: 225k
}
first_interviewee.first_name();
```

Very neat function that I wrote for the the 100 rust exercises book:

```rust
fn new(title: String, description: String, status: String) -> Self {
 let status_error = String::from("Only `To-Do`, `In Progress`, and `Done` statuses are allowed");
 assert!(status == "To-Do" || status == "In Progress" || status == "Done", "{}", status_error);
 if title.is_empty() == true && description.is_empty() == true {
 panic!("The 'Title' & 'Description' fields should not be empty.");
 }
 else if title.is_empty() == true {
 panic!("Title cannot be empty");
 }
 else if description.is_empty() == true{
 panic!("Description cannot be empty");
 }
 if title.capacity() > 50{
 panic!("Title cannot be longer than 50 bytes");
 }
 if description.capacity() > 500 {
 panic!("Description cannot be longer than 500 bytes");
 }
 Self {
 title,
 description,
 status,
 }
}
```

TIL asserts can be used to assert that a variable must equal some outcome, otherwise panic.
Super fun exercise
Three different type of rust collections(data types that store multiple pieces of data):
Vectors, hashmaps, strings.
Slices reference a contiguous set of data in a collection, instead of the whole collection. A slice
is a reference, and does not have ownership.
You can convert a value from one type to another using "as" operator

```rust
let c = (a as u8) + 32;
```

Remember that Strings are dynamically allocated in memory at runtime. String Slices are known
The data type for an array can be described as [T;N], where T is the type, N is the fixed length of
the array at compile time.
Tuples are immutable(cannot be changed after they are created) and can have multiple different
elements(strings, ints, etc)
Arrays are mutable, and are store the same element(homogenous)
static methods — methods that belong to a type itself are called using the :: operator.
I.e for the String type, having the method from; i.e String::from("testing!");
instance methods — methods that belong to an instance of a type are called using the .
operator.
An instance of a type would be a var named instance_var, as an example.
A struct is an objects data attributes; a great way to structure related data(i.e a person's
attributes).
Field inits allow you to create a struct using the parameters in the func, vs having to redeclare
the types:
I.e :

```rust
fn build_new_user(first_name:&'static str, last_name:&'static str,
email_address:&'static str, city:&'static str, state:&'static str) -> User {
 User {
 first_name,
 last_name,
 email_address,
 city,
 state,
 };
}
```

Vs.

```rust
fn build_new_user(first_name:&'static str, last_name:&'static str,
email_address:&'static str, city:&'static str, state:&'static str) -> User {
 User {
 first_name: first_name,
 last_name: last_name,
 email_address: email_address,
 city: city,
 state: state,
 }
}
```

Both are valid, option 1 just saves you time!
Struct update syntax and instances – creating multiple instances of a struct, and deciding when
to keep specific vals, i.e:

```rust
let user_1 = build_new_user("Adam", "Bouhmad", "adbouhmad@gmail.com", "Baltimore", "Maryland");
let user_2 = User {
 email_address: "adam.bouhmad@gmail.com",
 ..user_1
};
```

Super useful! We just need to remember that the data moves from user_1 to user_2, and that
we may not be able to use user_1 in the same way after user_2 is created because values may
be borrowed. In this case, they're not because we're using a static string slice that points to the
stack, and not the heap.
If we use the String data type, this doesnt work.

```rust
fn main(){
 let user_1 = build_new_user(String::from("Adam"), String::from("Bouhmad"),
String::from("adbouhmad@gmail.com"), String::from("Baltimore"),
String::from("Maryland"));
 let user_2 = User {
 first_name: String::from("joe"),
 ..user_1
 };
 println!("{}", user_1.city);
}
```

A tuple is an anonymous, ordered collection of values with different types. They're great for
temporary grouping of values.

```rust
let user: (i32, i32) = (1, 2);
```

A tuple struct is a named tuple; makes it easier to reference.

```rust
struct Color(i32, i32, i32);
```

We can also have different instances of the tuple struct
I.e

```rust
let black = Color(0, 0, 0);
```

Unit strucs are helpful when you want to declare a type, but dont have any data yet
I.e:

```rust
struct colors;
let rainbow = colors;
```

Spread syntax doesnt work inside functions, only when constructing a struct
I.e this wont work:

```rust
struct USER {
 firstname: String,
 lastname: String,
 age: i64,
}
fn main() {
 let mut user1 = define_struct(String::from("adam"), String::from("bouhmad"), 28);
 let mut user2 = define_struct(String::from("Caitlin"), ..user1);
}
```

But this will:

```rust
struct USER {
 firstname: String,
 lastname: String,
 age: i64,
}
fn main() {
 let mut user1 = USER {
 firstname: String::from("adam"),
 lastname: String::from("bouhmad"),
 age: 28
 };
 let mut user2 = USER {
 firstname: String::from("Caitlin"),
 ..user1
 };
}
```

example of tuple syntax:

```rust
fn main() {
 struct mytuple(String, String, i64);
 let mut tuple = mytuple(String::from("adam"), String::from("Bouhmad"), 28);
 println!("{}", tuple.1);
}
```

Destructuring unpacks values from complex data structures into into individual variables. Here's
a great example of a tuple being destructured:

```rust
fn main() {
 struct User(String, String, &'static str, i64);
 let adambouhmad = User(String::from("Adam"), String::from("Bouhmad"),
"adbouhmad@gmail.com", 28);
 let User(adambouhmad_firstname, adambouhmad_lastname, adambouhmad_email,
adambouhmad_age) = adambouhmad;
 println!("{}", adambouhmad_firstname);
}
```

You can have multiple methods for the same struct – neat!
Rust has automatic referencing and dereferencing, so that I dont have to dereference a pointer
when calling a method on an object, as an example. I'm still shaky on this concept, but at a high
level it makes sense to me.
Checking to see if a rectangle could be hypothetically stored inside another rectangle

```rust
struct Rectangle {
 width: i32,
 height: i32,
}
impl Rectangle{
 fn area(&self) -> i32{
 return self.width * self.height;
 println!("{}", self.width * self.height);
 }
 fn canhold(&self, someRectangle: Rectangle ) -> bool {
 self.width > someRectangle.width && self.height > someRectangle.height
 }
}
fn main() {
 let rectangle1: Rectangle = Rectangle {
 width: 100,
 height: 50,
 };
 let rectangle2: Rectangle = Rectangle {
 width: 500,
 height: 500,
 };
 println!("{}", rectangle1.canhold(rectangle2));
}
```

Struct practice using a chatgpt prompt as the question:
give me a quick prompt for a beginner in rust learning structs. i'll paste you my code as the
answer
ChatGPT said:
Sure! Here's a quick beginner-friendly Rust prompt on structs:
Create a Book struct with the fields: title (String), author (String), and pages (u32).
Then, write a function that takes a Book and prints out its details in a nice format.
Finally, in main(), create at least two Book instances and call your function on each.
Paste your code when you're ready!

```rust
struct Book {
 title: String,
 author: String,
 pages: u32,
}
impl Book {
 fn details(self){
 println!("Book Title: {}\n Author: {}\n Number of Pages: {}", self.title, self.author, self.pages);
 }
}
fn main() {
 let mut caitlins_book = Book {
 title: String::from("Fireweed in the Veil"),
 author: String::from("Caitlin Marie Andrews"),
 pages: 350,
 };
 let mut adams_book = Book {
 title: String::from("Eternal Optimism"),
 author: String::from("Adam Bouhmad"),
 pages: 250,
 };
 caitlins_book.details();
 println!("\n");
 adams_book.details();
}
```

Using an enum with variants is similar to defining multiple different structs. The benefit to using
an enum is if you have multiple variants of similar data, whereas a struct is helpful for defining
an object that has consistent attributes
- i.e a user will always have firstname, lastname, email – this is great to model using a
struct. An Ip Address may be IPv4 or IPv6. This is great to model with an enum.
NULL values do not exist in rust by default, but are included in the standard library using the
Option enum, which has the two types, Some or None.

```rust
let some_number = Some(5);
let some_char = Some('e');
let absent_number: Option<u32> = None;
```

Some_Number & Some_char don't have to have their types explicitly defined, because they're
inferred from the values provided(i.e Some(5) would default to a u32).
absent_number however has to have it's type explicitly defined(Option<u32>), as because the
value is None, there's no type inference!
You can not do evals/arithmatic against a variable of type Option<type> with a string/int/etc,
because they are not equivalent types. Rust expects you to handle the None case safely,
otherwise you can use the .unwrap() method. In other words, you have to convert Option<T> to
T before you do anything with it, otherwise, you go the memory safe route and convert your
value with type T to Option<T>.
ompare a value against a series of patterns and then execute code based on which pattern
matches.
Ok, so a really cool way to do comparison on values based on patterns & execute code based
on the patterns that have been matched is using the match statement(which sort of operates
like a switch statement in other languages, handling multiple cases).
Here's a great example. There are four coins in the US, pennies, nickels, dimes, and quarters. I
want to return the values for these coins.
First I'll create an enum in the global scope:

```rust
enum Coins {
Penny,
Nickel,
Dime,
Quarter,
}
```

Next, I'll create a function called coin_value, and create my match statements based on what's
passed into my coin_value function. I'll return the value.

```rust
fn coin_value(coin: Coins) -> u8 {
match coin {
Coins::Penny => 1,
Coins::Nickel => 5,
Coins::Dime => 10,
Coins::Quarter => 25,
}
}
```

Then I can call my function and pass in a Coin type of variant Penny, as an example.

```rust
println!("{}", coin_value(Coin::Penny));
```

I'll get back the value of 1.
The match expression is like a coin sliding machine, with the coins fitting into the first slots it fits
into.
Matches are exhaustive; the arm's patterns must cover all possibilities, including handling of
NONE(NULL) values.

```rust
if let Some(max) = config_max {
println!("The maximum is configured to be {max}");
}
```

This is saying:
"If config_max is a Some value, extract the inner value and bind it to the variable max, then run
the code inside the block."
This is the same as this:

```rust
match config_max {
Some(max) => println!("The maximum is configured to be {max}"),
None => (),
}
```

A create is the smallest amount of code the rust compiler considers at a time. It's important to
note that the compiler can consider a file to be a crate. There are two crates, library and binary
crates. Binary crates compile to an executable, so they must have an entry point. Library crates
ofc do not compile, and thus don't have a main function; instead they define functionality
intended to be shared with multiple projects. Rustaceans refer to crates often as libraries, not
the executables
- Rand is an example of a crate
A package is a bundle of one or more crates. A package must contain at least one crate,
whether that's a library or binary crate. So, to put it more bluntly, if a package contains
src/main.rs & src/lib.rs, it has two crates, a binary and a library.
A namespace is more or less a way to group related items under a common name. A great
example is folders.
The picture folder can have a file called notepad.txt, as can the desktop folder. However, once
they're out of those namespaces, they conflict.
So while a function is similar to a namespace, a namespace sort of abstracts the internal
implementations in rust. A module(mod) = a namespace
From chatgpt:
A namespace is a way to group related items (like functions, structs, and constants) under a
common name to keep code organized and avoid naming conflicts.
A great analogy is folders on your computer:
You can have a file called notes.txt in both the Documents folder and the Pictures folder
without a problem — because they're in different namespaces. But if you pull them both into
the same folder without renaming, you'll get a conflict.
In Rust, a mod (module) creates a namespace. It allows you to group related logic together and
access it using paths like garden::plant() or kitchen::plant().
While a function contains logic, a namespace contains items, including functions. It doesn't run
code — it just organizes it. So a function isn't the same as a namespace, but they work
together: a function lives inside a namespace (module).
Modules allow us to organize code for readability, & also control the privacy of items within
code, as definitions within a module are private by default. (you can use "pub" in front of your
definitions to make them public otherwise).
Both main.rs & lib.rs are crate roots.
- The reason for their name is that the contents of either of these two files form a module
named crate at the root of the crate's module structure, known as the module tree.
Here's an example module tree for the code below:
crate -> cafe
 -> equipment
 -> espresso_machine
 -> dishwashing_machine
 -> coffee_grinder
 -> steamer
 -> staff
 -> managers
 -> baristas
 -> roasters

```rust
mod cafe {
 mod equipment {
 fn espresso_machine() {}
 fn dishwashing_machine(){}
 fn coffee_grinder() {}
 fn steamer() {}
 }
 mod staff {
 fn managers() {}
 fn baristas() {}
 fn roasters() {}
 }
}
```

Starting with a module name means the path is relative. Starting with crate means it's absolute.
Think in terms of filesystems
Rust's module system feels a bit confusing/overly complicated(i.e super keyword to reference
module defined in the parent? But hopeful that this will click for me soon.
OK. New info unlocked, though I probably already typed this up.
crate refers to the root crate(the one youre using). Unless you're referring to modules defined
within your current crate(either binary or library) , refer to modules you want(that you defined in
lib.rs!) via:
use <crate_project_name>::mod::*;
as an example.
OK - and super is useful when REFERENCING MODULES IN A MODULE. So for example, in
lib.rs, I may have a function defined in a parent module like so:

```rust
mod back_of_house {
 pub enum Apps {
 Chicken,
 Fries,
}
mod inventory {
 pub fn eat_at_restauraunt() {
 let chicken_order = super::Apps::Chicken;
 }
}
}
```

Example of how to bring paths into scope using the use keyword:

```rust
mod animals {
 pub mod birds {
 pub fn parakeets() {}
 }
}
use crate::animals::birds::parakeets;
pub fn my_pets() {
 let my_bird = parakeets();
}
```

{:?} when printing means Print this thing using its debug representation(it's trait!). A trait is
essentially a collection of methods that define some behavior on an object
Similar to SQL - you can use the as keyword to use an alias for an object; a great usecase is
when youre using a module, and the type has the same name as another module(i.e
std::io::Result & std::fmt::Result).
You can import/use the module like so:
Use std::io::Result as ioResult
And then reference it as you wish.
You can also do this:

```rust
use std::fmt;
use std::io;
fn function1() -> fmt::Result {
 // --snip--
}
fn function2() -> io::Result<()> {
 // --snip--
}
```

, but I like the alias personally! Perhaps referencing the original module helps with readability
Glob operator is not recommended! It'll bring all public items in a path into scope - this could
bloat our binary.
Nested paths are great in that they help clean up your use lists and make them more readable.
Here's an example:
Previously, you imported Ordering & IO from the std library:

```rust
use std::cmp::Ordering;
use std::io;
```

You can clean this up by using nested paths to group your items:

```rust
use std::{cmp::Ordering, io};
```

That way, you clearly identify what items are coming from a specific modules/paths.
Rust's standard library has a data structure called collections - there are three types of
collections:
- String
  - A collection of characters~!
- HashMap
  - You can reference information using a key!
- Vectors
  - Large amount of numbers can be stored next to each other!
From chatgpt:
String
A growable, UTF-8 encoded collection of characters.
Vector (Vec<T>)
A growable array that stores values next to each other in memory — great for storing a list of
items of the same type.
HashMap (HashMap<K, V>)
A key-value store that lets you look up data by key, like a dictionary or map in other languages.
The memory stored here is stored in the heap - this means the data does not need to be known
at compile time, and can shrink and grow during runtime.

## Chapter 7

Vectors can only store data of the same type. Also, good to know that Vectors store information
next to each other in memory for easy, extremely fast access. Great data structure to use if you
have related data that you want to access very fast.
Vectors are considered to be generics, and thus you must define their type if you're not storing
data immediately; otherwise it doesn't know what type the objects the Vector will be storing is.
OK, so you can create a vector like so:

```rust
let mut related_data: Vec<i32> = Vec::new();
```

And then add data to the vector:

```rust
related_data.push(5);
related_data.push(6);
```

Thankfully there is a macro, vec!, that allows you to create a new vector and add data to it
immediately. Like so:

```rust
let my_vec: Vec<i32> = vec!(1,2,3,4);
```

You can iterate over a vector like so:

```rust
fn main() {
 let my_vector: Vec<i32> = vec!(1,2,3,4,5,6);
 for item in my_vector {
 println!("{item}");
 }
}
```

You can also modify the vector's current values as you'd like as you iterate, assuming the vector
is mutable!

```rust
fn main() {
 let mut my_vector: Vec<i32> = vec!(1,2,3,4,5,6);
 for item in &mut my_vector {
 *item += 10
 }
}
```

I still dont fully understand the &mut reference(and why you wouldnt just reference my_vector
by it's reference), but thats ok! More to figure out later.
Vectors only store values of the same type, but to get around this, you can define an enum
object, and multiple types of values within an enum, since an enum is considered a typed
object.
Below, we are able to print out any value inside of our vector by using match arms. The various
variables abstract the values; in rust these are called "bindings", as these variables(i, f, s) bind
to data inside each enum variant.

```rust
#[derive(Debug)]
enum SpreadsheetCell {
 Int(i32),
 Float(f64),
 String(String),
};
let mut my_vector: Vec<SpreadsheetCell> = vec!(SpreadsheetCell::Int(3), SpreadsheetCell::Float(3.2), SpreadsheetCell::String(String::from("Adam")));
let index = 1;
match my_vector.get(index) {
 Some(SpreadsheetCell::Int(i)) => println!("{}", i),
 Some(SpreadsheetCell::Float(f)) => println!("{}", f),
 Some(SpreadsheetCell::String(s)) => println!("{}", s),
 None => println!("nothing here"),
}
```

OK - TIL, but a Vector is implemented as a Struct in the Rust Standard Library.
- A growable array-like data structure
- Implemented as a struct in the standard library
Think of it like this(very simplified):

```rust
struct Vec<T> {
ptr: *mut T,
len: usize,
capacity: usize
}
```

Strings in Rust are sometimes seen as more complicated because of:
- Rusts proclivity for exposing possible errors
- Strings being a more complicated data structure that people give it credit for
- UTF-8
  - character encoding standard that represents Unicode characters
TIL: You can add a &str to a String, or a &str to another &str, but not a String to a String directly
— unless you use a reference. That's because the + operator for String is just syntactic sugar
for the .add() method, which is defined like this: fn add(self, s: &str) -> String
This means: The left-hand side (self) must be a String (and it will be moved), The right-hand
side must be a &str. The .add() method does take ownership of the left-hand side, but not the
right-hand side, it's just borrowed.
- s1 is moved into the add() method — you can't use s1 anymore after this.
- &s2 is just borrowed — you can still use s2 afterward.
Even through We pass a reference to an object of type string, the compiler uses something call
deref coercion to turn our String into a string slice(&str) at compile time.
Another working example:

```rust
fn main() {
 let tic = String::from("tic");
 let tac = String::from("tac");
 let toe = String::from("toe");
 let tic_tac_toe = tic + &tac + &toe;
 println!("{}", tic_tac_toe);
}
```

The format macro will make it easier for us as devs, as it automatically concatenates using
references of your String objects and returns a string:

```rust
fn main() {
 let tic = String::from("tic");
 let tac = String::from("tac");
 let toe = String::from("toe");
 let tic_tac_toe = format!("{tic}{tac}{toe}");
 println!("{}", tic_tac_toe);
}
```

With format using references, this call doesnt take ownership of any of the parameters
passed(tic, tac or toe objects).
The push method will just push a single char. push_str will push any str.
Although rust programming languages typically allow you to access individual chars in a string
by referencing their index, rust does not allow this because different languages encode their text
differently. I.e english characters(letters) may be represented with a byte each.
As an example. For the word "harry", if I were to try to reference the index of 0, i'd get the letter
"h".
However with languages like Cryllic, their encodings are different; each cryllic letter takes 2
bytes.
So the letter 3 in Cryllic wouldn't return 3 if i tried to reference the index of 0, instead it would
return half of the bytes for the letter 3, which is invalid utf-8. Rust avoids this unsafe action all
together as you could get a runtime panic, or land in the middle of a character, corrupting the
string.
Also, performance reasons in that it takes constant time to index strings(rust would have to walk
through the contents from the beginning to the index to determine how many valid chars there
are).
There are three ways to look at strings from Rust's perspective, bytes, grapheme clusters, and
scalar values.
Bytes: vector of u8 values
- Example: [224, 164, 168, 224]
Grapheme clusters: What humans see as a single character might be made of multiple chars.
- Example: [è, l, a t, e] [ e, `, l, a, t, e]
Scalar values: the letters that make up a specific word(they may not make sense on their own!
- Example: [è, l, a t, e]
Here's a great way to slice a string in rust:

```rust
fn main() {
 let my_string = String::from("my string, hell yeah!");
 let slicing_strings = &my_string[0..];
 for character in slicing_strings.chars(){
 println!("{character}");
 }
}
```

Or:

```rust
fn main() {
 let the_word_apple = String::from("apple");
 let sliced_apple = &the_word_apple[0..];
 for character in sliced_apple.chars() {
 println!("{character}");
 }
}
```

Valid unicode chars must be made up of at least 1 byte.
Retrieve the bytes from a character using the bytes method:

```rust
fn main() {
 let apple = String::from("apple crisp");
 let sliced_apple = &apple[0..];
 for bytes in sliced_apple.bytes() {
 println!("{bytes}");
 }
}
```

HashMaps are basically python dictionaries - HashMaps are key value stores:
HashMap<K, V>; storing a mapping of keys of type K to values of type V.
HashMaps store their information in the heap, just like Vectors do. HashMaps are also in the
collections portion of the standard library.

```rust
use std::collections::HashMap;
```

HashMaps have less support than vectors - there's no built-in macro to help construct them.
One example of messing around with HashMaps. Keep in mind that the get method returns an
Option<&V> - if there's no value, it'll return None.

```rust
fn main() {
 let mut team_scores: HashMap<String, i32> = HashMap::new();
 team_scores.insert(String::from("Morocco"), 3);
 team_scores.insert(String::from("Ireland"), 3);
 let moroccan_team = String::from("Morocco");
 let score = team_scores.get(&moroccan_team).copied().unwrap_or(0);
 println!("{}", score);
}
```

Example of how to iterate over HashMaps:

```rust
fn main() {
 let mut team_scores: HashMap<String, i32> = HashMap::new();
 team_scores.insert(String::from("Morocco"), 3);
 team_scores.insert(String::from("Ireland"), 3);
 let moroccan_team = String::from("Morocco");
 let score = team_scores.get(&moroccan_team).copied().unwrap_or(0);
 for (key, value) in &team_scores {
 println!("{key}: {value}");
 }
}
```

The code below is not valid, as we attempt to borrow a value at the very end(printing
secret_name), despite it having been moved/owned by the HashMap secrets:

```rust
fn main() {
 let secret_name = String::from("firstname");
 let secret_value = String::from("dsodfnodswe23!@fjsd@#@!#$fdsk");
 let mut secrets: HashMap<String, String> = HashMap::new();
 secrets.insert(secret_name, secret_value);
 for (name, value) in secrets {
 println!("{name}: {value}");
 }
 println!("{}", secret_name);
}
```

This can become valid if we make the clone the variable secrets_name, as an example, as
we're inserting it into the secrets HashMap.
secret_value's ownership is not relinquished however it seems. ** ACTION to dig into this.

```rust
use std::collections::HashMap;
fn main() {
 let secret_name = String::from("firstname");
 let secret_value = String::from("dsodfnodswe23!@fjsd@#@!#$fdsk");
 let new_secret_value = String::from("mysupersecretpassphrase");
 let mut secrets: HashMap<String, String> = HashMap::new();
 secrets.insert(secret_name.clone(), secret_value);
 secrets.insert(secret_name, new_secret_value);
 for (name, value) in secrets {
 println!("{name}: {value}");
 }
 println!("{}", secret_value);
}
```

HashMap uses a hashing function called SipHash that provides protection to DoS attacks
involving hash tables. It's not the fastest hashing algo, but the security benefits are a reasonable
trade-off. Youn can specify a different hasher if youre interested.
A hasher is a type that implements the BuildHasher trait.
A singleton is a design pattern where a class has only one instance, and is available globally.
See:
https://www.reddit.com/r/rust/comments/18x9nxg/comment/lcddbkh/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button
- "they make it hard to reason about the behavior of a single function without having to
consider the entire state of the program, and they make things hard to test."
Look into mutable statics(????)
https://doc.rust-lang.org/reference/items/static-items.html#mutable-statics
If you try to use a Struct in a HashMap, it must have Eq, Hash, and PartialEq traits
implemented, as to store the keys and values efficiently, they need Hash, and then for
comparisons rust needs Eq and Partial Eq.
Eq, PartialEq, and Hash are traits implemented on String, &str, i32,u32,usize, u8(etc), bool,
chars. Not on floats however(they just have PartialEq)
Rust can't guess what nice, or human-readable means as it's very subjective, so you have to
implement your own Display trait on your struct if you'd like to display it cleanly.
An Application factory is a function(or closure) that creates a new App instance every time the
server starts a new worker thread. This is in the contex of an Actix HHTP server.
Inside match arms, you can name the data inside Ok() & Err() anything, as you're just binding
that something to a particular name. The name doesn't matter, it's the structure you're matching,
specifically the Enum variants Ok or Err — not the names you give to the contents(i.e file or
error)
Create an array with 100 items:

```rust
let a = [0; 100];
```

I still struggle with Strings and slices, tuples, arrays and vectors & remembering their methods,
ways to destructure, etc.
Access tuple values using dot , i.e second_value.1
One way of iterating through a vector:

```rust
input.iter().map(|element| element + 1).collect()
```

Another way:

```rust
for element in input {
 output.push(element * 2);
}
```

TODO:
- Revisit Enums, Vectors, Strings, Tuples
- Get very comfortable with their methods & traits
Enums store data in variations.
Rust Programming Tutorial #10 - Enum Types
as_str()to convert a String to a string slice(&str)
to_string()to convert a string slice(&str) to a String
format example to concatenate a str:

```rust
format!("{}", input + " world!")
```

Parallelism is about running code in parallel on several CPUs.
Concurrency is about breaking a problem into separate, independent parts.
These are not the same thing—single-core machines have been running code concurrently for
half a century now—but they are related. So much online well akshually-ing ignores how we
often break programs into concurrent pieces so that those pieces can run in parallel, and
interleave in ways that keep our cores crunching! (If we didn't care about performance, why
would we bother?)
- From: https://bitbashing.io/async-rust.html
Threads + queues = Channels(think SSH Channels)
- Allows proccesses to send each other information
  - Avoids deadlocks, race conditions, helpful for error handling, etc
- Threads enjoy process-like isolation from the rest of the program since they don't share
memory.
- Threads have a set of inputs and outputs in the form of channels they receive from and
channels they send to
  - Channels let you get visibility into each thread's throughput
- Channels are the synchronization. If a channel is empty, the receiver waits until it's not. If
the channel is full, the sender waits. Threads never sleep while they have a job to do,
and gracefully pause if they've outpaced the rest of the system.

## ASYNC

Sync programming is like a chef boiling water, and waiting for the water to boil before doing
anything else
Async is like a chef boiling water, and chopping vegetables while he waits for the water to come
up to temp. Its like having a chef multi-task.
Unlike other languages(i.e python), Rust doesn't have a built-in async runtime, just creates like
tokio & async-std. Rust uses async & .wait to mark code that can be paused & resumed later
Async functions are not executed immediately. Instead, they return a future
The most commonly used runtime, tokio, provides an attribute macro so that you can make your
main function async:
.await only works on future types. This means you can only await async-aware future functions,
ones that return future.
This means that the standard library sleep can not be awaited:

```rust
use std::{thread::sleep, time::Duration};
const sleep_time: u64 = 20;
#[tokio::main]
async fn main() {
 sleep_timer();
 println!("Sleep timer is currently running. Please wait {} seconds", sleep_time);
}
async fn sleep_timer() {
 sleep(Duration::from_secs(sleep_time)).await;
 println!("{} seconds have passed!", sleep_time);
}
```

However the tokio sleep can be:

```rust
use tokio::time::{sleep, Duration};
const sleep_time: u64 = 20;
#[tokio::main]
async fn main() {
 sleep_timer().await;
 println!("Sleep timer is currently running. Please wait {} seconds", sleep_time);
}
async fn sleep_timer() {
 sleep(Duration::from_secs(sleep_time)).await;
 println!("{} seconds have passed!", sleep_time);
}
```

Interesting tidbit – await does not mean run this operation in the background. Instead it means
execute this asynchronous computation now, and pause here until its completion.
Other tasks can still run, but any code after the await will not run until the await finishes. A
practical example would be an async download continuing to run while the sleep timer is
awaited. The print statement would not follow until the that async computation is completed.
UNLESS WE USED TOKIO SPAWN
.await executes the work a future describes
.await is different from blocking because it suspends the task, not the thread. Other tasks can
run, and thus the need for spawn.
"While async and await allow you to write asynchronous code that doesn't block, they don't
automatically make that code run in parallel. To achieve true concurrency, you need to use
tokio::spawn to create separate tasks that can run concurrently on the Tokio runtime's executor."
Reqwest is an extremely popular "Batteries Included" HTTP client Library for Rust. It's built on
top of Tokio & Hyper. It supports the following:
- Async GET/POST requests
- Setting headers, query params
- Streaming and body parsing
- JSON deserialization with serde
- Timeouts, retries, cookies, and more
A typical call looks like the following:

```rust
let response = reqwest::get("https://some.api.com/thing").await?;
```

- Kicks off a non-blocking request
- Suspends your task until the HTTP response arrives
- Returns a Response object you can work with

```rust
let response = reqwest::get("https://some.api.com/player").await?;
let player: Player = response.json().await?;
```

- .get().await:
You hear a knock and open the door — the delivery person hands you a sealed box.
- .json().await:
You open the box and pull out the thing you ordered.
Rust uses the serde crate, specifically serde::Deserialize, to map fields by name and type.

JSON Field Struct Field Type Match? Notes
"userId" userId u32
"id" id u32
"title" title String
"body" body String

Because all the field names match exactly (case-sensitive), and the types are compatible, serde
can derive Deserialize automatically — no extra config needed.
