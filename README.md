# Java 21+ Extreme Optimization: 10+1 Golden Rules

[![EN](https://img.shields.io)](README.en.md)
[![RU](https://img.shields.io)](README.md)

> **Манифест инженера: Как заставить JVM летать, а Native Image - быть компактным.**

# ТОП-10+1 "Золотых правил оптимизаций Java 21+" (JVM + Native)

Этот репозиторий содержит примеры кода и подробный разбор 11 золотых правил оптимизации для Java 21+, Spring Boot 3 и GraalVM Native Image.

Работая с кодом, я не раз ловил азарт: а как этот метод можно ускорить ещё? Какую гайку подкрутить, чтобы JVM не просто работала, а буквально летела? Что изменить в архитектуре, чтобы Native Image стал ещё компактнее, а холодный старт – ещё быстрее?

Испытав этот азарт оптимизации не раз, я хочу поделиться им с вами. Я собрал квинтэссенцию своего опыта в конкретный чек-лист.

Это не просто советы по стилю кода. Это "10+1 Золотых правил оптимизации Java 21+".

Это те рычаги, которые заставляют JIT-компилятор петь, а GraalVM – генерировать бинарники с хирургической точностью.

Приготовьтесь! Мы начинаем оптимизировать!

---

### Содержание

1. [Правило №1. Records как DTO (Immutability & Heap)](#правило-1-records-как-dto-immutability--heap)
2. [Правило №2. fillInStackTrace(null) в бизнес-исключениях](#правило-2-fillinstacktracenull-в-бизнес-исключениях)
3. [Правило №3. Final везде](#правило-3-final-везде)
4. [Правило №4. Смерть Рефлексии (AOT-friendly)](#правило-4-смерть-рефлексии-aot-friendly)
5. [Правило №5. Короткие методы (Inlining Threshold)](#правило-5-короткие-методы-inlining-threshold)
6. [Правило №6. Преаллокация коллекций](#правило-6-преаллокация-коллекций)
7. [Правило №7. BigDecimal vs Long (Битва за примитивы)](#правило-7-bigdecimal-vs-long-битва-за-примитивы)
8. [Правило №8. Избегайте прокси в критических узлах](#правило-8-избегайте-прокси-в-критических-узлах)
9. [Правило №9. Generics: Избегаем лишних кастов](#правило-9-generics-избегаем-лишних-кастов)
10. [Правило №10. Статический анализ вместо динамического (MapStruct)](#правило-10-статический-анализ-вместо-динамического-mapstruct)
11. [Правило №11. Scoped Values вместо ThreadLocal](#правило-11-scoped-values-вместо-threadlocal)

## Правило №1. Records как DTO (Immutability & Heap)
**В чём боль:** Обычные POJO с сеттерами – это "чёрный ящик". Компилятор постоянно начеку: вдруг кто-то изменит состояние объекта в середине метода? Это мешает глубокой оптимизации.

**Золотое решение:** Используйте record для всех данных, которые просто "летят" сквозь систему.

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

> **Голос JIT:** "О, record! Наконец-то я вижу final поля по умолчанию. Теперь я точно знаю, что username не изменится после создания. Я могу спокойно выкинуть лишние проверки и заинлайнить доступ к данным прямо в регистры процессора".

## Правило №2. fillInStackTrace(null) в бизнес-исключениях
**В чём боль:** Мы часто используем Exception для логики (например, UserNotFound). Но создание исключения – это не просто создание объекта, это дорогое "путешествие" по всему стеку вызовов.

**Золотое решение:** Для бизнес-ошибок переопределите сбор стектрейса.

```java
public class EntityNotFoundException extends RuntimeException {
    public EntityNotFoundException(String message) {
        super(message);
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
```

> **Голос JIT:** "Спасибо! Когда вы создаёте обычное исключение, я вынужден бросить всё и побайтово восстанавливать цепочку вызовов. Этот как ставить фильм на паузу, чтобы пересчитать все кадры. С этим правилом я просто создаю объект и бегу дальше".

## Правило №3. Final везде
**В чём боль:** Неопределённость. Если переменная не помечена как final, компилятор должен учитывать возможность её изменения, даже если в реальности этого не происходит.

**Золотое решение:** Делайте final локальные переменные, параметры и поля. Это не только про производительность, но и про предсказуемость. Оптимизированный код – это прежде всего предсказуемый код.

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
> **Голос JIT:** "Вижу final – делаю Constant Folding. Если я уверен, что переменная неизменна, я могу выкинуть лишние проверки из машинного кода. Для меня final – это не ограничение, а зелёный свет: "Здесь безопасно, жми на газ!".

## Правило №4. Смерть Рефлексии (AOT-friendly)
**В чём боль:** Рефлексия – это "чёрная дыра". JIT не может заглянуть внутрь вызова, а Native Image и вовсе требует описывать каждый такой чих в JSON-конфигах.

**Золотое решение:** Используйте MapStruct, JOOQ и другие библиотеки для генерации кода. Они генерируют чистый Java-код на этапе компиляции, который выглядит так, будто вы написали его руками.

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

> **Голос JIT:** "Рефлексия для меня – это как туман на трассе. Я снижаю скорость до минимума. А код от MapStruct – это прямой автобан. Я вижу entity.getName() -> dto.setName() и просто "прошиваю" этот вызов насквозь".

## Правило №5. Короткие методы (Inlining Threshold)
**В чём боль:** Гигантские методы на 500 строк, которые делают всё: валидируют, считают, логируют и сохраняют. JIT не может их "проглотить" (встроить один в другой), потому что они превышают лимиты по размеру байт-кода. В итоге каждый вызов этого метода – это честный переход по адресу в памяти, создание фрейма в стеке и куча лишних тактов.

**Золотое решение:** Дробите логику на мелкие методы. Идеальный размер для инлайнинга – до 35 байт байт-кода.

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

> **Голос JIT:** "У меня есть жёсткий лимит MaxInlineSize. Если метод крохотный, я просто копирую его тело в место вызова. Границы исчезают, код становится монолитным и летит со скоростью света. Огромные методы я вынужден вызывать "по старинке" – медленно и печально. Будьте проще, и я сделаю ваш код монолитным по производительности.

## Правило №6. Преаллокация коллекций
**В чём боль:** Создавая new ArrayList<>(), new HashMap<>() и другие структуры данных без параметров, вы подписываете JVM на серию "переездов". Как только список наполняется, он создаёт массив побольше и копирует туда данные. Это лишние аллокации и работа для GC.

**Золотое решение:** Задавайте Initial Capacity.

```java
private Mono<ServerResponse> renderErrorResponse(ServerRequest request) {
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

> Голос JIT: "Каждый раз, когда массив внутри коллекции расширяется, я слышу плач Garbage Collector’a. Заранее заданный размер – это как забронированный столик в ресторане: никакой суеты и лишних движений. Просто работаем".

## Правило №7. BigDecimal vs Long (Битва за примитивы)
**В чём боль:** BigDecimal – это тяжёлый объект, внутри которого лежит массив int[]. Любая операция с ним – это создание нового объекта. В биллинге или высоконагруженных расчётах это генерирует тонны мусора в памяти.

**Золотое решение:** Храните денежные значения в минимальных единицах (копейки, центы) в типе long. Переходите на BigDecimal только в самый последний момент – при выводе пользователю.

```java
public record WalletResponse(
    long amount, // long - это быстро
    String currency
) {
    // Только для красоты при выводе
    public BigDecimal getDisplayAmount() {
        return BigDecimal.valueOf(amount, 2);
    }
}
```

> Голос JIT: "long – это просто 64 бита в моём регистре. Я храню его прямо в регистрах процессора. Сложение двух long занимает доли наносекунды. С BigDecimal я вынужден прыгать в кучу (Heap) за каждым числом. Выбирайте long, если не хотите, чтобы я буксовал на арифметике".

## Правило №8. Избегайте прокси в критических узлах
**В чём боль:** @Transactional и @Async создают обертки в рантайме. Это лишние вызовы в стеке и лишние объекты. В высоконагруженных циклах это "стек-киллер".

**Золотое решение:** Выносите логику обработки данных в методы без аннотаций, оставляя @Transactional только на верхнем уровне.

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

> Голос JIT: "Прокси для меня – это лабиринт. Я вижу цепочку сгенерированных классов-оберток, через которые нужно продраться к реальному коду. Чем меньше магии между мной и логикой, тем лучше я смогу оптимизировать граф вызовов и заинлайнить методы".

## Правило №9. Generics: Избегаем лишних кастов
**В чём боль:** Хотя в рантайме типы стираются (Erasure), использование Object или Raw Types заставляет вас (и JVM) постоянно делать checkcast. Это не только небезопасно, но и заставляет процессор тратить лишние циклы на проверку иерархии классов.

**Золотое решение:** Используйте конкретные типы там, где важна производительность. Это позволяет JIT-компилятору заранее знать структуру данных и строить оптимальный машинный код.

```java
@RequiredArgsConstructor
@Component
public class ValidatorHandler {

    private final Validator validator;

    // Использование <T> гарантирует, что на выходе будет тот же тип, что и на входе
    // Никаких ручных (Cast) в вызывающем коде!
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

> Голос JIT: "Каждый раз, когда я вижу checkcast, я должен остановиться и проверить: а точно ли этот объект в памяти совпадает с ожидаемым типом? С правильными дженериками я доверяю вашему коду на 100%. Для меня это дорога без светофоров".

## Правило №10. Статический анализ вместо динамического (MapStruct)
**В чём боль:** Библиотеки вроде ModelMapper или злоупотребление ObjectMapper.convertValue() используют рефлексию и интроспекцию в рантайме. Они буквально "ощупывают" каждый объект, пытаясь найти подходящие поля. Это медленно для JIT и требует огромных конфигов для Native Image.

**Золотое решение:** Используйте кодогенерацию. MapStruct генерирует обычный Java-код target.set(source.get()) на этапе компиляции. Мы уже видели его мощь в Правиле №4, но здесь подчеркнём: нулевой оверхед в рантайме.

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

> Голос JIT: "Для меня код от MapStruct – это подарок. Это прямой, понятный и предсказуемый код. Я инлайню его мгновенно, превращая маппинг в практически бесплатную операцию. Никаких поисков по именам полей, только работа с регистрами и прямой доступ к памяти".

## Правило №11. Scoped Values вместо ThreadLocal
**В чём боль:** Раньше мы хранили контекст пользователя или транзакции в ThreadLocal. Это работало, когда потоков было 200. Но в Java 21 вы включаете spring.threads.virtual.enabled: true и запускаете 100_000 потоков. Если каждый из них "присосётся" к объекту в ThreadLocal, ваш Heap лопнет быстрее, чем сработает первый GC.

**Золотое решение:** Используйте Scoped Values (JEP 446). Они позволяют передать данные вниз по дереву вызовов. Как только выполнение выходит из блока – память мгновенно освобождается.

```java
private final static ScopedValue<UserContext> CURRENT_USER = ScopedValue.newInstance();

public void handleRequest(UserContext context) {
    // Привязываем данные к области видимости. (Scope)
    ScopedValue.where(CURRENT_USER, context).run(() -> {
        // Внутри этого блока и всех вложенных методов
        // CURRENT_USER.get() вернёт наш контекст.
        // Никаких утечек, никакой привязки к жизни потока!
        processOrder();
    });
}
```

> Голос JIT: "ThreadLocal – это тяжёлый рюкзак, который поток не снимает до самой смерти. Scoped Value – это лёгкая эстафетная палочка: подержал, передал, и она исчезла. В мире миллиона потоков это единственный способ не утонуть в памяти".

## Финал: Слово AOT
Мы закончили наш список. Теперь, как и договаривались, выпускаем на сцену "судью".

> **AOT:** "Друзья, я всё видел. Пока вы пишете код, я строю его карту. Если вы соблюдаете эти правила, мой статический анализ проходит гладко, а бинарник получается лёгким и быстрым.
> Обо всех неоднозначных моментах – будь то забытая рефлексия или динамический прокси – я сообщу вам либо на этапе компиляции, либо уже в процессе работы. Мой вердикт прост: пишите прозрачно, и я сделаю вашу Java быстрее нативного C++".

## Резюме-таблица для тех, кто крутит:

| №  | Золотое правило               | Профит для JVM (JIT)                                  | Профит для Native Image (AOT)                              |
|----|-------------------------------|-------------------------------------------------------|------------------------------------------------------------|
| 1  | **Record вместо POJO**        | Агрессивный инлайнинг final полей.                    | Быстрый статический анализ графа объектов.                 |
| 2  | **fillInStackTrace(null)**    | Экономия CPU (в 10-50 раз) при создании Exception.    | Меньше нативного кода для обхода стека в бинарнике.        |
| 3  | **Final везде**               | Constant Folding (вычисления на этапе компиляции).    | Более компактный и предсказуемый код.                      |
| 4  | **Смерть Рефлексии**          | Прямые вызовы методов без поиска в рантайме.          | **Критично:** Избавляет от громоздких reflect-config.json. |
| 5  | **Короткие методы**           | Гарантированное встраивание (inlining).               | Оптимизация размера исполняемого файла.                    |
| 6  | **Преаллокация**              | Меньше пауз Garbage Collector на "переезды" массивов. | Снижение пикового потребления RAM.                         |
| 7  | **Long вместо BigDecimal**    | Работа на регистрах CPU без аллокаций в куче.         | Радикальное уменьшение объёма живых объектов.              |
| 8  | **Минимум прокси**            | Прозрачный граф вызовов без интерцепторов.            | Меньше динамической генерации байт-кода.                   |
| 9  | **Чёткие Generics**           | Отказ от лишних проверок типов (checkcast).           | Упрощение статической типизации при сборке.                |
| 10 | **CodeGen вместо Reflection** | Скорость прямого присваивания a = b.                  | Нулевой оверхед: никакой магии в рантайме.                 |
| 11 | **Scoped Values**             | Безопасная передача контекста в Virtual Threads.      | Стабильный Heap при миллионах потоков.                     |

**Голос AOT (финальный аккорд):**

> "Посмотрите на эту таблицу. Если ваш проект следует этим правилам, я соберу его в бинарник, который стартует за миллисекунды. Если нет – я сообщу вам о каждой "грязной" рефлексии или прокси, либо на этапе компиляции, либо прямо в лоб во время работы.
> Выбор за вами!"
