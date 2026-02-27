# Java 21+ Extreme Optimization: 10+1 Golden Rules

![](images/image_1.jpg)

[![EN](https://img.shields.io)](README.en.md)
[![RU](https://img.shields.io)](README.md)

> **An Engineer's Manifesto: How to Make the JVM Fly and Native Images Be Compact.**

# TOP 10+1 "Golden Rules for Java 21+ Optimization" (JVM + Native)

This repository contains code examples and a deep dive into 11 golden rules of optimization for Java 21+, Spring Boot 3, and GraalVM Native Image.

While working with code, I’ve often felt that surge of excitement: how can I make this method even faster? Which bolt can I tighten to make the JVM not just run, but literally fly? What architectural changes will make the Native Image even more compact and the cold start even faster?

Having experienced this thrill of optimization many times, I want to share it with you. I’ve distilled my experience into a specific checklist.

This isn’t just about code style. These are the "10+1 Golden Rules for Java 21+ Optimization".

These are the levers that make the JIT compiler sing and GraalVM generate binaries with surgical precision.

Get ready! We are starting the optimization!

---

### Table of Contents

1. [Rule #1. Records as DTOs (Immutability & Heap)](#rule-1-records-as-dtos-immutability--heap)
2. [Rule #2. fillInStackTrace(null) in Business Exceptions](#rule-2-fillinstacktracenull-in-business-exceptions)
3. [Rule #3. Final Everywhere](#rule-3-final-everywhere)
4. [Rule #4. The Death of Reflection (AOT-friendly)](#rule-4-the-death-of-reflection-aot-friendly)
5. [Rule #5. Short Methods (Inlining Threshold)](#rule-5-short-methods-inlining-threshold)
6. [Rule #6. Collection Pre-allocation](#rule-6-collection-pre-allocation)
7. [Rule #7. BigDecimal vs Long (The Battle for Primitives)](#rule-7-bigdecimal-vs-long-the-battle-for-primitives)
8. [Rule #8. Avoid Proxies in Critical Paths](#rule-8-avoid-proxies-in-critical-paths)
9. [Rule #9. Generics: Avoiding Excessive Casts](#rule-9-generics-avoiding-excessive-casts)
10. [Rule #10. CodeGen instead of Reflection (MapStruct)](#rule-10-codegen-instead-of-reflection-mapstruct)
11. [Rule #11. Scoped Values over ThreadLocal](#rule-11-scoped-values-over-threadlocal)

## Rule #1. Records as DTOs (Immutability & Heap)
**The Pain Point:** Standard POJOs with setters are a "black box". The compiler is always on guard: what if someone changes the object’s state in the middle of a method? This prevents deep optimizations.
**The Golden Solution:** Use record for all data that simply "flows" through the system.

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

> **JIT’s Voice:** "Oh, a record! Finally, I see final fields by default. Now I know for sure that the username won’t change after creation. I can safely discard redundant checks and inline data access directly into CPU registers."

## Rule #2. fillInStackTrace(null) in Business Exceptions
**The Pain Point:** We often use Exceptions for business logic (e.g., UserNotFoundException). But creating an exception is more than just object allocation – it’s a costly "journey" through the entire call stack.
**The Golden Solution:** For business-level errors, override the stack trace collection.

```java
public class EntityNotFoundException extends RuntimeException {
    public EntityNotFoundException(String message) {
        super(message);
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        // We don't collect the stack trace, saving CPU cycles
        return this;
    }
}
```

> **JIT’s Voice:** "Thank you! When you create a standard exception, I’m forced to drop everything and byte-by-byte reconstruct the call chain. It’s like pausing a movie to recount every single frame. With this rule, I just create the object and keep running."

## Rule #3. Final Everywhere
**The Pain Point:** Uncertainty. If a variable isn’t marked as final, the compiler must account for the possibility of it changing, even if it never actually does.
**The Golden Solution:** Make local variables, parameters, and fields final. This isn’t just about performance, it’s about predictability. Optimized code is, above all, predictable code.

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

> **JIT’s Voice:** "I see final – I perform Constant Folding. If I’m certain a variable is immutable, I can strip redundant checks from the machine code. To me, final isn’t a restriction, it’s a green light: "It’s safe here, floor it!"

## Rule #4. The Death of Reflection (AOT-friendly)
**The Pain Point:** Reflection is a "black hole". JIT cannot see inside the call, and Native Image requires you to describe every such "sneeze" in bulky JSON configurations.
**The Golden Solution:** Use MapStruct, JOOQ, and other code generation libraries. They produce clean Java code at compile-time that looks exactly as if you wrote it by hand.

```java
@Mapper(componentModel = MappingConstants.ComponentModel.SPRING,
        unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface UserMapper {

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

> **JIT’s Voice:** "To me, Reflection is like fog on a highway. I have to slow down to a crawl. But code from MapStruct is a straight autobahn. I see entity.getName() -> dto.setName() and I simply "stitch" this call right through."

## Rule #5. Short Methods (Inlining Threshold)
**The Pain Point:** Gigantic 500-line methods that do everything: validate, calculate, log, and save. JIT cannot "swallow" them (inline one into another) because they exceed bytecode size limits. As a result, every call to such a method is a full-blown memory jump, a stack frame creation, and wasted CPU cycles.
**The Golden Solution:** Break logic into small methods. The ideal size for inlining is up to 35 bytes of bytecode.

```java
@Before("@annotation(AuthoriseUserCreateByAnonymous)")
public void validateRoleTypeForAnonymousUserCreate(JoinPoint joinPoint) {
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

> **JIT’s Voice:** "I have a strict MaxInlineSize limit. If a method is tiny, I just copy its body into the call site. The boundaries disappear, the code becomes monolithic, and it flies at the speed of light. I’m forced to call huge methods ‘the old-fashioned way’ – slowly and sadly. Keep it simple, and I’ll make your code monolithic in performance."

## Rule #6. Collection Pre-allocation
**The Pain Point:** By creating a new ArrayList<>() or new HashMap<>() without parameters, you’re signing the JVM up for a series of "relocations". As the collection fills, it creates a larger array and copies the data. These are redundant allocations and extra work for the GC.
**The Golden Solution:** Always set the Initial Capacity.

```java
private Mono<ServerResponse> renderErrorResponse(ServerRequest request) {
    // Pre-allocating with 16 slots
    Map<String, Object> errorProperties = new LinkedHashMap<>(16);

    errorProperties.putAll(getErrorAttributes(request,
            ErrorAttributeOptions.defaults()));

    int status =
            (int) errorProperties.getOrDefault("status", 500);

    return ServerResponse.status(status)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(errorProperties)
            .doOnNext(resp -> log.error("Ошибка запроса: [{}]: {}",
                    status,
                    errorProperties));
}
```

> **JIT’s Voice:** "Every time an internal array expands, I hear the Garbage Collector cry. A pre-defined size is like a reserved table at a restaurant: no fuss, no extra movement. Just pure work."

## Rule #7. BigDecimal vs Long (The Battle for Primitives)
**The Pain Point:** BigDecimal is a heavy object with an int[] array inside. Every operation creates a new object. In billing or high-load calculations, this generates tons of memory "garbage".
**The Golden Solution:** Store monetary values in the smallest units (cents) as a long. Switch to BigDecimal only at the very last moment – when displaying to the user.

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

> **JIT’s Voice:** "A long is just 64 bits in my register. I store it directly in CPU registers. Adding two longs takes fractions of a nanosecond. With BigDecimal, I’m forced to jump into the Heap for every single number. Choose long if you don’t want me to stall on arithmetic."

## Rule #8. Avoid Proxies in Critical Paths
**The Pain Point:** @Transactional and @Async create wrappers at runtime. These are extra stack calls and extra objects. In high-load loops, this is a "stack-killer".
**The Golden Solution:** Move data processing logic into methods without annotations, leaving @Transactional only at the top level.

```java
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
public class UserService {

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

> **JIT’s Voice:** "To me, a Proxy is a labyrinth. I see a chain of generated wrapper classes I have to fight through to reach the real code. The less magic between me and your logic, the better I can optimize the call graph and inline your methods."

## Rule #9. Generics: Avoiding Excessive Casts
**The Pain Point:** Although types are erased at runtime (Erasure), using Object or Raw Types **forces** you (and the JVM) to constantly perform checkcast. This is not only unsafe but also makes the CPU waste cycles checking class hierarchies.
**The Golden Solution:** Use specific types where performance matters. This allows the JIT to know the data structure in advance and build optimal machine code.

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

> **JIT’s Voice:** "Every time I see a checkcast, I have to stop and verify: does this object in memory actually match the expected type? With proper Generics, I trust your code 100%. To me, it’s a highway without traffic lights."

## Rule #10. CodeGen instead of Reflection (MapStruct)
**The Pain Point:** Libraries like a ModelMapper, or the misuse of ObjectMapper.convertValue(), rely on reflection and introspection at runtime. They literally "grope" every object trying to find matching fields. This is slow for JIT and requires massive configs for Native Image.
**The Golden Solution:** Use code generation. MapStruct generates standard Java code target.set(source.get()) at compile-time. No runtime overhead.

```java
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
@RestController
public class UserController {

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

> **JIT’s Voice:** "MapStruct code is a gift. It’s direct, clear, and predictable. I inline it instantly, turning mapping into a practically free operation. No field name lookups, just register work and direct memory access."

## Rule #11. Scoped Values over ThreadLocal
**The Pain Point:** We used to store user or transaction context in ThreadLocal. This worked when we had 200 threads. But in Java 21, you enable spring.threads.virtual.enabled: true and launch 100,000 threads. If each "clings" to an object in ThreadLocal, your Heap will burst before the first GC kicks in.
**The Golden Solution:** Use Scoped Values (JEP 446). They allow data to be passed down the call tree. As soon as execution leaves the block – the memory is instantly freed.

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

> **JIT’s Voice:** "ThreadLocal is a heavy backpack that a thread never takes off until it dies. Scoped Value is a light relay baton: you hold it, pass it, and it’s gone. In a world of a million threads, it’s the only way not to drown in memory."

## Final Summary Table

| #   | Golden Rule                 | JVM Profit (JIT)                             | Native Image Profit (AOT)                   |
|-----|-----------------------------|----------------------------------------------|---------------------------------------------|
| 1   | **Records over POJO**       | Aggressive inlining of final fields.         | Fast static object graph analysis.          |
| 2   | **fillInStackTrace(null)**  | CPU savings (10-50x) on Exception creation.  | Less native code for stack walking.         |
| 3   | **Final Everywhere**        | Constant Folding (compile-time calculation). | More compact and predictable code.          |
| 4   | **The Death of Reflection** | Direct method calls without runtime lookups. | **Critical**: Removes bulky reflect-config.json |
| 5   | **Short Methods**           | Guaranteed inlining.                         | Binary size optimization.                   |
| 6   | **Pre-allocation**          | Fewer GC pauses on array resizing.           | Lower peak RAM consumption.                 |
| 7   | **Long over BigDecimal**    | CPU register work without Heap allocations.  | Radical reduction in live object volume.    |
| 8   | **Minimize Proxies**        | Transparent call graph without interceptors. | Less dynamic bytecode generation.           |
| 9   | **Strict Generics**         | Removal of redundant checkcast checks.       | Simplified static typing during build.      |
| 10  | **CodeGen over Reflection** | Speed of direct a = b assignment.            | Zero overhead: no runtime magic.            |
| 11  | **Scoped Values**           | Safe context passing for Virtual Threads.    | Stable Heap with millions of threads.       |

**Final: The Word of AOT**
We’ve reached the end of our list. Now, as promised, let’s bring the "Judge" to the stage.
> **AOT’s Voice:** "Friends, I’ve seen it all. While you write code, I build its complete map. If you follow these rules, my static analysis runs smoothly, and the resulting binary is lightweight and fast.
> I will notify you of any ambiguity – be it forgotten reflection or a dynamic proxy – either at compile-time or right in your face during execution. My verdict is simple: write transparently, and I will make your Java faster than native C++."
