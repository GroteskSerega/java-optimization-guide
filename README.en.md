# Java 21+ Extreme Optimization: 10+1 Golden Rules

![](images/image_1.jpg)

[![EN](https://img.shields.io)](README.en.md)
[![RU](https://img.shields.io)](README.md)

> **An Engineer's Manifesto: Making JVMs Fly and Native Images Lean.**

# TOP 10+1 "Golden Rules for Java 21+ Optimization: Making JIT Sing and GraalVM Soar"

This repository contains code examples and a deep dive into 11 golden rules of optimization for Java 21+, Spring Boot 3, and GraalVM Native Image.

Why does your Java system stutter where it should soar? We're used to trusting JVM "magic", but in the era of Java 21 and Native Image, the rules of the game have shifted. From micro-optimizing bytecode to the radical paradigm shift of Scoped Values - we're breaking down 11 "golden rules" that force the JIT to sing and your binaries to launch in milliseconds. No fluff, just hardcore engineering, CPU registers, and the "voices" of compilers embedded in your code.

While working with code, I’ve often felt that surge of excitement: how can I make this method even faster? Which bolt can I tighten to make the JVM not just run, but literally fly? What architectural changes will make the Native Image even more compact and the cold start even faster?

Having experienced this thrill of optimization many times, I want to share it with you. I’ve distilled my experience into a specific checklist.

This isn’t just about code style. These are the "**10+1 Golden Rules for Java 21+ Optimization**".

These are the levers that make the JIT compiler sing and GraalVM generate binaries with surgical precision.

Get ready! We are starting the optimization!

---

### Table of Contents

1. [Rule #1. Records as DTOs (Immutability & Heap)](#rule-1-records-as-dtos-immutability--heap)
2. [Rule #2. fillInStackTrace(null) in Business Exceptions](#rule-2-fillinstacktracenull-in-business-exceptions)
3. [Rule #3. Final Everywhere (Predictability is Key)](#rule-3-final-everywhere-predictability-is-key)
4. [Rule #4. The Death of Reflection (AOT-Friendly)](#rule-4-the-death-of-reflection-aot-friendly)
5. [Rule #5. Short Methods (The Inlining Threshold)](#rule-5-short-methods-the-inlining-threshold)
6. [Rule #6. Pre-allocating Collections](#rule-6-pre-allocating-collections)
7. [Rule #7. BigDecimal vs Long (The Battle for Primitives)](#rule-7-bigdecimal-vs-long-the-battle-for-primitives)
8. [Rule #8. Minimize Proxies in Hot Paths](#rule-8-minimize-proxies-in-hot-paths)
9. [Rule #9. Generics: Eliminating Redundant Casts](#rule-9-generics-eliminating-redundant-casts)
10. [Rule #10. Static Analysis Over Runtime Discovery (MapStruct)](#rule-10-static-analysis-over-runtime-discovery-mapstruct)
11. [Rule #11. Scoped Values instead of ThreadLocal](#rule-11-scoped-values-instead-of-threadlocal)

## Rule #1. Records as DTOs (Immutability & Heap)
**The Pain Point:** Standard POJOs with setters are a "black box". The compiler must stay on high alert: what if someone changes the object’s state in the middle of a method? This uncertainty hinders deep optimization and complicates object graph analysis.
**The Golden Solution:** Use `record` for all data that simply "flows" through the system.

```java
public record UserUpsertRequest (

        @NotBlank(message = VALIDATE_USER_USERNAME_BLANK)
        @Size(min = NAME_SIZE_MIN, max = NAME_SIZE_MAX, message = VALIDATE_USER_USERNAME_INCORRECT_SIZE)
        @Pattern(regexp = LATIN_REGEX, message = VALIDATE_USER_USERNAME_INCORRECT_REGEX)
        String username,

        @NotBlank(message = VALIDATE_USER_PASSWORD_BLANK)
        @Size(min = PASSWORD_SIZE_MIN, max = PASSWORD_SIZE_MAX, message = VALIDATE_USER_PASSWORD_INCORRECT_SIZE)
        String password,

        @NotBlank(message = VALIDATE_USER_FIRSTNAME_BLANK)
        @Size(min = NAME_SIZE_MIN, max = NAME_SIZE_MAX, message = VALIDATE_USER_FIRSTNAME_INCORRECT_SIZE)
        @Pattern(regexp = CYRILLIC_REGEX, message = VALIDATE_USER_FIRSTNAME_INCORRECT_REGEX)
        String firstName,

        @Size(min = NAME_SIZE_MIN, max = NAME_SIZE_MAX, message = VALIDATE_USER_SECONDNAME_INCORRECT_SIZE)
        @Pattern(regexp = CYRILLIC_REGEX, message = VALIDATE_USER_SECONDNAME_INCORRECT_REGEX)
        String secondName,

        @NotBlank(message = VALIDATE_USER_LASTNAME_BLANK)
        @Size(min = NAME_SIZE_MIN, max = NAME_SIZE_MAX, message = VALIDATE_USER_LASTNAME_INCORRECT_SIZE)
        @Pattern(regexp = CYRILLIC_REGEX, message = VALIDATE_USER_LASTNAME_INCORRECT_REGEX)
        String lastName,

        @NotBlank(message = VALIDATE_USER_EMAIL_BLANK)
        @Size(min = NAME_SIZE_MIN, max = NAME_SIZE_MAX, message = VALIDATE_USER_EMAIL_INCORRECT_SIZE)
        @Email(regexp = EMAIL_REGEX, message = VALIDATE_USER_EMAIL_INCORRECT_REGEX)
        String email
) {

}
```

> **JIT’s Voice:** "Oh, a record! Finally, I see `final` fields by default. Now I know for certain that the data won’t change after instantiation. I can apply **Scalar Replacement** more aggressively -- deconstructing the object into individual variables - and inline access directly into CPU registers."

> **AOT's Whisper:** "Since the structure of a record is known to me at build time, I can optimize the mapping of this data into binary code far more aggressively than for ordinary classes with their dynamic nature."

## Rule #2. fillInStackTrace(null) in Business Exceptions
**The Pain Point:** We often use exceptions for flow control (e.g., `UserNotFoundException`). But creating an exception isn't just about object allocation -- it’s an expensive "journey" through the entire call stack to populate the `StackTraceElement[]` array. This process can account for up to 90% of an exception's lifecycle cost.
**The Golden Solution:** For predictable business errors where you don't need a log filled with framework internals, override the stack trace collection. Using the specific `RuntimeException` constructor makes it even faster.

```java
public class EntityNotFoundException extends RuntimeException {
    public EntityNotFoundException(String message) {
        // Even faster via constructor: message, cause, enableSuppression, writableStackTrace
        super(message, null, false, false);
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        // We don't collect the stack trace, saving CPU cycles
        return this;
    }
}
```

> **JIT’s Voice:** "Thank you! When you create a standard exception, I’m forced to drop everything and reconstruct the call chain byte by byte. It’s like pausing a movie just to count every single frame. With this rule, I simply instantiate the object and move on, maintaining peak execution momentum."

> **AOT's Whisper:** "In Native Image, every stack trace is additional meta-code I must be able to reconstruct at runtime. By removing `fillInStackTrace`, you're not just speeding up logic -- you're making my binary leaner by stripping away redundant metadata tables."

## Rule #3. Final Everywhere (Predictability is Key)
**The Pain Point:** Uncertainty. If a variable isn’t marked as `final`, the compiler must account for the possibility of its state changing at any moment. This bloats the state graph that needs to be analyzed during optimization, making the compiler's job much harder.
**The Golden Solution:** Make local variables, method parameters, and class fields `final` by default. Optimized code is, above all, predictable code. The fewer variables can change their state, the more aggressively the optimizers can work their magic.

```java
public Resource exportDataToCsvResource() {
    final List<Statistics> data = statisticsRepository.findAll();

    final StringBuilder builder = new StringBuilder(data.size() * 64);

    builder.append(FIRST_ROW_OF_CSV);

    for (final Statistics stat : data) {
        builder.append(stat.getId()).append(DELIMITER_CSV)
                .append(stat.getType()).append(DELIMITER_CSV)
                .append(stat.getUserId()).append(DELIMITER_CSV)
                .append(stat.getCheckIn()).append(DELIMITER_CSV)
                .append(stat.getCheckOut()).append(DELIMITER_CSV)
                .append(stat.getCreatedAt()).append('\n');
    }

    final byte[] bytes = builder.toString().getBytes(StandardCharsets.UTF_8);
    return new ByteArrayResource(bytes);
}
```

> **JIT’s Voice:** "When I see `final`, I perform **Constant Folding**. If I’m certain that an object reference or a primitive value won't change, I can strip redundant checks from the machine code and even pre-calculate the results of certain operations. To me, `final` isn’t a restriction -- it’s a green light: "It’s safe here, floor it!"

> **AOT's Whisper:** "For me, `final` is the foundation for **Dead Code Elimination**. If I see a constant condition, I can simply prune entire code branches that will never execute. This makes the binary smaller and the execution logic much more straightforward."

## Rule #4. The Death of Reflection (AOT-Friendly)
**The Pain Point:** Reflection is a performance "black hole". JIT cannot look inside a `Method.invoke()` call ahead of time, and Native Image forces you to explicitly document every such "sneeze" in bulky JSON configurations. If you use reflection in a hot path, you are voluntarily leaving 30-50% of your potential throughput on the table.
**The Golden Solution:** Leverage **MapStruct**, **JOOQ**, and other Annotation Processing (APT) libraries. They generate clean Java code during compilation that looks exactly as if you'd written it by hand -- with direct getter and setter calls.

```java
@Mapper(componentModel = MappingConstants.ComponentModel.SPRING,
        unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface UserMapper {
    // Standard mapping methods as shown above...
    User requestToUser(UserUpsertRequest request);

    UserResponse userToResponse(User user);

    default UserListResponse userListToUserListResponse(List<User> users) {
        return new UserListResponse(users
                .stream()
                .map(this::userToResponse)
                .toList());
    }

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "username", ignore = true)
    @Mapping(target = "password", ignore = true)
    @Mapping(target = "roles", ignore = true)
    @Mapping(target = "createAt", ignore = true)
    @Mapping(target = "updateAt", ignore = true)
    void updateUser(UserUpsertRequest request, @MappingTarget User user);
}
```

> **JIT’s Voice:** "Reflection is like thick fog on a highway; I can't see what's ahead, so I slow down to a crawl and **disable** my optimizations. But MapStruct code is a straight autobahn. I see `entity.getName()` -> `dto.setName()` and I simply punch straight through that call using **inlining**."

> **AOT's Whisper:** "Reflection is my worst nightmare. To make it work in a Native Image, I have to carry around a ton of metadata, which bloats the binary. Code generation lets me prune the dead weight at build time. Less reflection means a smaller `reflect-config.json` and a lightning-fast startup."

## Rule #5. Short Methods (The Inlining Threshold)
**The Pain Point:** Gigantic, 500-line methods that try to do everything: validate, calculate, log, and save. The JIT cannot "swallow" them (inline them into one another) because they exceed bytecode size limits. Consequently, every call to such a method is a full-blown memory jump, involving stack frame creation and wasted CPU cycles.
**The Golden Solution:** Break logic into granular methods. The ideal size for inlining is **up to 35 bytes of bytecode**. Suddenly, "Clean code" isn't just about readability -- it's the fastest way for the machine to execute your logic.

```java
@Before("@annotation(AuthoriseUserCreateByAnonymous)")
public void validateRoleTypeForAnonymousUserCreate(JoinPoint joinPoint) {
    // Logic split into small, focused methods as shown in the example...
    HttpServletRequest request = getRequest();

    loggingOperation(joinPoint, request);

    Authentication auth = getAuth();

    if (!auth.getName().equals(ANONYMOUS_USER)) {
        AppUserPrincipal principal =
                ((AppUserPrincipal) auth.getPrincipal());

        if (isAdmin(principal)) {
            return;
        }

        throw new ForbiddenException(TEMPLATE_OPERATION_FORBIDDEN);
    }

    if (isRoleTypeUser(joinPoint)) {
        return;
    }

    throw new ForbiddenException(TEMPLATE_OPERATION_FORBIDDEN);
}

private HttpServletRequest getRequest() {
    RequestAttributes requestAttributes =
            RequestContextHolder.getRequestAttributes();

    if (requestAttributes == null) {
        throw new ForbiddenException(TEMPLATE_OPERATION_FORBIDDEN);
    }

    return ((ServletRequestAttributes) requestAttributes).getRequest();
}

private void loggingOperation(JoinPoint joinPoint,
                              HttpServletRequest request) {
    Map<String, String> pathVariables =
            (Map<String, String>) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);

    Authentication auth =
            SecurityContextHolder.getContext().getAuthentication();

    log.info(CALL_OPERATION,
            auth.getName(),
            joinPoint.getSignature().getName(),
            pathVariables.toString(),
            Arrays.toString(joinPoint.getArgs()));
}

private Authentication getAuth() {
    return SecurityContextHolder.getContext().getAuthentication();
}

private AppUserPrincipal getUserDetails() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    if (auth == null || !auth.isAuthenticated()) {
        throw new UserNotAuthenticatedException(TEMPLATE_OPERATION_UNAUTHORIZED);
    }

    return (AppUserPrincipal) auth.getPrincipal();
}
```

> **JIT’s Voice:** "I have a strict **MaxInlineSize** limit. If a method is tiny, I just copy its body directly into the call site. Method boundaries dissolve, the code becomes a contiguous block, and it flies at the speed of light. I’m forced to call huge methods "the old-fashioned way" -- with all the overhead of jumping to addresses and saving stack states. Keep it simple, and I’ll make your code truly fast."

> **AOT's Whisper:** "In Native Image, I perform deep reachability analysis. Small methods allow me to precisely determine which parts of the program will never be called, allowing me to prune them during the build. The cleaner your method structure, the leaner and faster the resulting binary."

## Rule #6. Pre-allocating Collections
**The Pain Point:** Creating a `new ArrayList<>()`, `new HashMap<>()`, or other data structures without parameters signs the JVM up for a series of "relocations". As the collection fills, it must allocate a larger array and copy the old data into it. These are redundant allocations, memory fragmentation, and extra work for the Garbage Collector.
**The Golden Solution:** Always set the **Initial Capacity**. In Java 19+, even more convenient static methods have been introduced that automatically account for the **Load Factor**.

```java
private Mono<ServerResponse> renderErrorResponse(ServerRequest request) {
    // Pre-allocating 16 buckets using the modern factory method (Java 19+)
    Map<String, Object> errorProperties = LinkedHashMap.newLinkedHashMap(16);

    errorProperties.putAll(getErrorAttributes(request,
            ErrorAttributeOptions.defaults()));

    int status =
            (int) errorProperties.getOrDefault("status", 500);

    return ServerResponse.status(status)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(errorProperties)
            .doOnNext(resp -> log.error("Request error: [{}]: {}",
                    status,
                    errorProperties));
}
```

> **JIT’s Voice:** "Every time an internal array expands, I hear the Garbage Collector's lament. A pre-defined size is like a reserved table at a restaurant: no fuss, no extra movement. Just allocate one block of memory and work with it peacefully, without being distracted by shuffling bytes around."

> **AOT's Whisper:** "In Native Image, memory management is even more rigorous. Pre-allocation allows me to better predict your application's peak RAM consumption. The fewer dynamic array expansions you have, the more stable and predictable your binary behaves under load."

## Rule #7. BigDecimal vs Long (The Battle for Primitives)
**The Pain Point:** `BigDecimal` is a heavyweight object with an internal `int[]` array. Every arithmetic operation creates a brand-new object in memory. In billing systems or high-throughput calculations, this generates heaps of garbage, forcing the Garbage Collector to work overtime.
**The Golden Solution:** Store monetary values in the smallest units (cents) as a long. Switch to BigDecimal only at the very last moment -- when displaying to the user.

```java
public record WalletResponse(
    long amount, // primitive long is lightning fast
    String currency
) {
    // Only for UI/API display
    public BigDecimal getDisplayAmount() {
        return BigDecimal.valueOf(amount, 2);
    }
}
```

> **JIT’s Voice:** "A `long` is just 64 bits in my register; I can keep it directly in CPU registers. Adding two `longs` takes fractions of a nanosecond. With `BigDecimal`, I’m forced to jump into the Heap for every single number and its scale. Choose `long` if you don’t want me to stumble over basic arithmetic."

> **AOT's Whisper:** "In a Native Image binary, working with `long` often compiles down to a single assembly instruction. `BigDecimal`, on the other hand, drags along a tree of dependencies and complex memory management logic. The more primitives you use, the smaller my executable becomes and the faster it 'warms up'."

## Rule #8. Minimize Proxies in Hot Paths
**The Pain Point:** `@Transactional`, `@Async` and `@Cacheable` are incredibly convenient, but behind the scenes, they create dynamic wrappers (Proxies) at runtime. Every call to a proxied method involves an extra "hop" through interceptor objects, a bloated call stack, and the loss of deep inlining potential. In high-throughput loops, this becomes a literal **"stack-killer"**.
**The Golden Solution:** Keep your core business logic "pure". Use annotations only at the top-level **Entry Points** (like Controller or Service facades), while internal service logic should call standard `private` or `package-private` methods. If you feel the need to call a `@Transactional` method from within the same class, remember that the proxy won't even trigger (**self-invocation**) -- this is a perfect signal to refactor and decompose your logic.

```java
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
public class UserService {
    // Standard Spring Service with clean internal calls as shown above...

    @Value("${app.kafka.kafkaStatisticsService.kafkaUserCreatedStatus}")
    private String kafkaUserCreatedStatus;

    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;

    private final UserMapper userMapper;

    private final KafkaTemplate<String, Object> kafkaTemplate;

    public List<User> findAll(UserFilter userFilter) {
        return userRepository.fetchAll(
                UserSpecification.withFilter(userFilter),
                PageRequest.of(
                        userFilter.pageNumber(),
                        userFilter.pageSize()
                )
        ).getContent();
    }

    public User findById(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() ->
                        new EntityNotFoundException(MessageFormat.format(TEMPLATE_USER_NOT_FOUND_EXCEPTION, id)));
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException("Username not found!"));
    }

    @AuthoriseUserCreateByAnonymous
    @Transactional
    public UUID save(User user, RoleType roleType) {
        // Business logic here...
        // Heavy operations without inner proxy calls
        userRepository.findUserIdByUsernameAndEmail(
                user.getUsername(),
                user.getEmail()
        ).ifPresent(id -> {
                    throw new UserAlreadyExistsException(
                            MessageFormat.format(TEMPLATE_USER_ALREADY_EXISTS_EXCEPTION,
                                    user.getUsername(),
                                    user.getEmail()));
        });

        user.setRoles(new ArrayList<>(List.of(roleType)));
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        UUID userId = userRepository.saveAndFlush(user).getId();

        TransactionSynchronizationManager.registerSynchronization(
                new TransactionSynchronization() {
                    @Override
                    public void afterCommit() {
                        kafkaTemplate.send(kafkaUserCreatedStatus,
                                new UserRegistrationEvent(userId)
                        );
                    }
                }
        );

        return userId;
    }

    @AuthoriseUserUpdateAndDelete
    @Transactional
    public UUID update(UUID userId, UserUpsertRequest request, RoleType roleType) {
        User existedUser = findById(userId);

        userMapper.updateUser(request, existedUser);

        if (request.password() != null && !request.password().isBlank()) {
            existedUser.setPassword(passwordEncoder.encode(request.password()));
        }

        if (roleType != null) {
            existedUser.getRoles().clear();
            existedUser.getRoles().add(roleType);
        }

        return userRepository.saveAndFlush(existedUser).getId();
    }

    @AuthoriseUserUpdateAndDelete
    @Transactional
    public void delete(UUID id) {
        findById(id);

        userRepository.deleteById(id);
    }
}
```

> **JIT’s Voice:** "A Proxy is a labyrinth for me. I see a chain of generated wrapper classes that I have to fight through just to reach the actual code. The less magic there is between me and your logic, the faster I can build a direct call graph and apply **Inlining**."

> **AOT's Whisper:** "Dynamic proxies are my public enemy number one. To make them work in a Native Image, I either have to generate them ahead of time or carry a heavy reflection mechanism. By reducing unnecessary proxies, you shrink the number of generated classes in the binary and significantly accelerate application startup."

## Rule #9. Generics: Eliminating Redundant Casts
**The Pain Point:** Although types are erased at runtime (**Type Erasure**), using `Object` or **Raw Types** forces you (and the JVM) to constantly insert the `checkcast` instruction into the bytecode. Not only is this unsafe, but it also forces the CPU to waste cycles verifying class hierarchies every single time you access the object.
**The Golden Solution:** Use strictly typed Generics wherever performance is critical. This allows the compiler to guarantee types at build time and enables the JIT compiler to generate machine code without unnecessary "checkpoints".

```java
@RequiredArgsConstructor
@Component
public class ValidatorHandler {

    private final Validator validator;

    // Using <T> ensures the output type matches the input
    // No manual (Casts) in the calling code!
    public <T> Mono<T> validate(T body) {
        return Mono.fromCallable(() -> {
                    var violations = validator.validate(body);

                    if (violations.isEmpty()) {
                        return body;
                    }

                    throw new ValidationException(buildErrorMessage(violations));
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    private String buildErrorMessage(Set<? extends ConstraintViolation<?>> violations) {
        return violations
                .stream()
                .map(v ->
                        v.getPropertyPath() + ": " +
                                v.getMessage())
                .collect(Collectors.joining("; "));
    }
}
```

> **JIT’s Voice:** "Every time I see a `checkcast`, I'm forced to downshift and verify: does this object in memory actually match the expected type? With proper Generics, I trust your code 100%. For me, it’s a high-speed highway without traffic lights and ID checks."

> **AOT's Whisper:** "In Native Image, I perform a global **Static Analysis** of the entire program. Strict typing helps me define type boundaries more accurately and eliminate redundant checks from the binary. The fewer 'unknown' `Object` types I encounter, the fewer runtime type checks I need to bake into the executable."

## Rule #10. Static Analysis Over Runtime Discovery (MapStruct)
**The Pain Point:** Libraries like `ModelMapper`, or the misuse of `ObjectMapper.convertValue()` impose a "dynamic tax" on performance. They rely on runtime introspection, literally "groping" every object to find matching fields via `getField()` and `setAccessible(true)`. For the JIT, this code is opaque; for Native Image, it's a configuration nightmare spanning thousands of lines.
**The Golden Solution:** Shift all complexity to the compilation stage. Use code generation. **MapStruct** generates standard Java code `target.set(source.get())` at compile-time. As we saw in Rule #4, this results in **zero runtime overhead** and total transparency for the optimizers.

```java
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
@RestController
public class UserController {
    // Controller logic using generated mappers as shown above...
    private static final String pathToUserResource = "/api/v1/user/{id}";

    private final UserMapper userMapper;

    private final UserService userService;

    @GetMapping
    public ResponseEntity<UserListResponse> findAll(@Valid UserFilter userFilter) {
        return ResponseEntity.ok(
                userMapper.userListToUserListResponse(
                        userService.findAll(userFilter)
                )
        );
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserResponse> findById(@PathVariable UUID id) {
        // Direct call to generated code. Zero reflection.
        return ResponseEntity.ok(
                userMapper.userToResponse(userService.findById(id))
        );
    }

    @PostMapping
    public ResponseEntity<Void> create(@RequestBody @Valid UserUpsertRequest request,
                                               @RequestParam RoleType roleType) {
        return ResponseEntity.created(getUri(
                userService.save(
                        userMapper.requestToUser(request),
                        roleType
                )
        )).build();
    }

    @PutMapping("/{id}")
    public ResponseEntity<Void> update(@PathVariable("id") UUID userId,
                                       @RequestBody @Valid UserUpsertRequest request,
                                       @RequestParam RoleType roleType) {
        return ResponseEntity.ok()
                .location(getUri(
                        userService.update(userId,
                                request,
                                roleType)
                ))
                .build();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable("id") UUID userId) {
        userService.delete(userId);
        return ResponseEntity.noContent().build();
    }

    private URI getUri(UUID id) {
        return UriComponentsBuilder.fromPath(pathToUserResource)
                .buildAndExpand(id)
                .toUri();
    }
}
```

> **JIT’s Voice:** "MapStruct code is a gift. It’s a direct, clear, and predictable stream of instructions. I inline these methods instantly, turning mapping into a practically 'free' operation. No searching through metadata HashMaps -- just pure CPU register work."

> **AOT's Whisper:** "Static analysis is my best friend. Since MapStruct generates standard method calls, I can see every connection between classes during the build. I don't have to guess which fields you might 'touch' via reflection, so I can boldly prune everything else from the final binary."

## Rule #11. Scoped Values instead of ThreadLocal
**The Pain Point:** For decades, we've stored user or transaction context in `ThreadLocal`. This worked when we had 200-500 threads. But in Java 21, you enable `spring.threads.virtual.enabled: true` and launch 100_000 virtual threads. If each one "clings" to a heavyweight object in `ThreadLocal`, your Heap will burst before the first GC cycle even kicks in. Furthermore, ThreadLocal is a mutable structure, which inherently complicates optimization.
**The Golden Solution:** Use **Scoped Values** (JEP 446 / 464). They allow you to safely pass immutable data down the call tree. As soon as execution leaves the block, the data becomes unreachable, and the memory is instantly ready for reclamation. No more leaks due to a forgotten `.remove()`.

```java
private final static ScopedValue<UserContext> CURRENT_USER = ScopedValue.newInstance();

public void handleRequest(UserContext context) {
    // Bind data to the scope
    ScopedValue.where(CURRENT_USER, context).run(() -> {
        // Inside this block, CURRENT_USER.get() works.
        // No leaks, no attachment to thread lifetime!
        processOrder();
    });
}
```

> **JIT’s Voice:** "`ThreadLocal` is a heavy backpack that a thread never takes off until it dies -- and I can never predict when that will be. A `Scoped Value` is a lightweight relay baton: you hold it, you pass it, and then it’s gone. In a world of a million virtual threads, this is the only way to avoid drowning in endless thread-local maps."

> **AOT's Whisper:** "Since a Scoped Value's lifetime is strictly bound to a code block, I can analyze object lifecycles far more efficiently. This helps me optimize memory allocation and reduce context-switching overhead in the native binary."

## Final Summary Table

| #   | Golden Rule                 | JVM Profit (JIT)                                 | Native Image Profit (AOT)                         |
|-----|-----------------------------|--------------------------------------------------|---------------------------------------------------|
| 1   | **Records over POJO**       | Aggressive inlining of `final` fields.           | Fast static object graph analysis.                |
| 2   | **fillInStackTrace(null)**  | CPU savings (10-50x) on Exception creation.      | Less native code for stack walking.               |
| 3   | **Final Everywhere**        | **Constant Folding** (compile-time calculation). | More compact and predictable code.                |
| 4   | **The Death of Reflection** | Direct method calls without runtime lookups.     | **Critical**: Removes bulky `reflect-config.json` |
| 5   | **Short Methods**           | Guaranteed **Inlining**.                         | Binary size optimization (pruning).               |
| 6   | **Pre-allocation**          | Fewer GC pauses on array "relocations".          | Lower peak RAM consumption.                       |
| 7   | **Long over BigDecimal**    | CPU register work without Heap allocations.      | Radical reduction in live object volume.          |
| 8   | **Minimize Proxies**        | Transparent call graph without interceptors.     | Less dynamic bytecode generation.                 |
| 9   | **Strict Generics**         | Removal of redundant `checkcast` checks.         | Simplified static typing during build.            |
| 10  | **CodeGen over Reflection** | Speed of direct `a = b` assignment.              | **Zero Overhead**: no runtime magic.              |
| 11  | **Scoped Values**           | Safe context passing for Virtual Threads.        | Stable Heap with millions of threads.             |

**Final: The Word of AOT**
We’ve reached the end of our list. Now, as promised, let’s bring the "Judge" to the stage.
> **AOT’s Voice:** "Friends, I’ve seen it all. While you write code, I build its complete blueprint. If you follow these rules, my static analysis runs smoothly, and the resulting binary is lightweight and fast.
> I will notify you of any ambiguity -- be it forgotten reflection or a dynamic proxy -- either at compile-time or right in your face during execution. My verdict is simple: **write transparently, and I will make your Java faster than native C++**."
