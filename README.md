# Java 21+ Extreme Optimization: 10+1 Golden Rules

![](images/image_1.jpg)

[![EN](https://img.shields.io)](README.en.md)
[![RU](https://img.shields.io)](README.md)

> **Манифест инженера: Как заставить JVM летать, а Native Image - быть компактным.**

# ТОП-10+1 "Золотых правил оптимизаций Java 21+: как заставить JIT петь, а GraalVM - летать"

Этот репозиторий содержит примеры кода и подробный разбор 11 золотых правил оптимизации для Java 21+, Spring Boot 3 и GraalVM Native Image.

Почему ваша Java-система буксует там, где должна летать? Мы привыкли доверять магии JVM, но в мире Java 21 и Native Image правила игры изменились. От микро-оптимизаций байт-кода до радикальной смены парадигмы с Scoped Values – разбираем 11 "золотых правил", которые заставят JIT петь, а ваш бинарник – стартовать за миллисекунды. Никакой "воды", только хардкор, регистры процессора и "голоса" компиляторов внутри вашего кода.

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
**В чём боль:** Обычные POJO с сеттерами – это "чёрный ящик". Компилятор постоянно начеку: вдруг кто-то изменит состояние объекта в середине метода? Это мешает глубокой оптимизации и усложняет анализ графа объектов.

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

> **Голос JIT:** "О, record! Наконец-то я вижу final поля по умолчанию. Теперь я точно знаю, что данные не изменится после создания. Я могу агрессивнее применять **Scalar Replacement** (разложить объект на переменные) и заинлайнить доступ к ним прямо в регистры процессора".

> **Шёпот AOT:** "Поскольку структура record известна мне ещё на этапе сборки, я могу оптимизировать маппинг этих данных в бинарный код гораздо агрессивнее, чем для обычных классов с их динамической природой".

## Правило №2. fillInStackTrace(null) в бизнес-исключениях
**В чём боль:** Мы часто используем Exception для логики (например, UserNotFound). Но создание исключения – это не просто создание объекта, это дорогое "путешествие" по всему стеку вызовов для заполнения массива StackStraceElement[]. На это уходит до 90% времени "жизни" исключения.

**Золотое решение:** Для предсказуемых бизнес-ошибок, где вам не нужен лог со всеми внутренностями фреймворка, переопределите сбор стектрейса.

```java
public class EntityNotFoundException extends RuntimeException {
    public EntityNotFoundException(String message) {
        super(message, null, false, false); // ещё быстрее через конструктор
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        // Мы не собираем трассировку стека, что позволяет экономить ресурсы CPU
        return this;
    }
}
```

> **Голос JIT:** "Спасибо! Когда вы создаёте обычное исключение, я вынужден бросить всё и побайтово восстанавливать цепочку вызовов. Этот как ставить фильм на паузу, чтобы пересчитать все кадры. С этим правилом я просто создаю объект и бегу дальше, сохраняя темп выполнения".

> **Шёпот AOT:** "В Native Image каждый стектрейс – это дополнительный мета-код, который я должен уметь восстанавливать в рантайме. Убирая _fillInStackTrace_, вы не только ускоряете логику, но и делаете мой бинарник компактнее, избавляя меня от лишних таблиц метаданных".

## Правило №3. Final везде
**В чём боль:** Неопределённость. Если переменная не помечена как _final_, компилятор должен учитывать возможность её изменения в любой момент. Это раздувает граф состояний, который нужно анализировать при оптимизации.

**Золотое решение:** Делайте _final_ локальные переменные, параметры методов и поля классов. Оптимизированный код – это прежде всего предсказуемый код. Чем меньше переменных могут изменить своё состояние, тем агрессивнее работают оптимизаторы.

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
> **Голос JIT:** "Вижу _final_ – делаю **Constant Folding**. Если я уверен, что ссылка на объект или значение переменной не изменится, я могу выкинуть лишние проверки из машинного кода и даже заранее вычислить результат некоторых операций. Для меня final – это не ограничение, а зелёный свет: "Здесь безопасно, жми на газ!".

> **Шёпот AOT:** "Для меня _final_ – это база для **Dead Code Elimination**. Если я вижу константное условие, я могу просто "отрезать" целые ветки кода, которые никогда не исполнятся. Это делает бинарный файл меньше, а логику - прямолинейнее".

## Правило №4. Смерть Рефлексии (AOT-friendly)
**В чём боль:** Рефлексия – это "чёрная дыра" для производительности. JIT не может заранее заглянуть внутрь вызова через _Method.invoke()_, а Native Image и вовсе требует описывать каждый такой "чих" в JSON-конфигах. Если вы используете рефлексию в критическом узле, вы добровольно отказываетесь от 30-50% потенциальной скорости.

**Золотое решение:** Используйте **MapStruct**, **JOOQ** и другие библиотеки, работающие через кодогенерацию (APT). Они создают чистый Java-код на этапе компиляции, который выглядит так, будто вы написали его руками - с прямыми вызовами геттеров и сеттеров.

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

> **Голос JIT:** "Рефлексия для меня – это как туман на трассе. Я не вижу, что впереди и снижаю скорость до минимума, отключая все свои суперспособности. А код от MapStruct – это прямой автобан. Я вижу _entity.getName()_ -> _dto.setName()_ и просто "прошиваю" этот вызов насквозь через **Inlining**".

> **Шёпот AOT:** "Рефлексия – мой ночной кошмар. Чтобы она заработала в Native Image, мне нужно тащить за собой кучу метаданных, что раздувает бинарник. Кодогенерация позволяет мне выкинуть всё лишнее ещё при сборке. Меньше рефлексии – меньше reflect-config.json и быстрее старт".

## Правило №5. Короткие методы (Inlining Threshold)
**В чём боль:** Гигантские методы на 500 строк, которые делают всё: валидируют, считают, логируют и сохраняют. JIT не может их "проглотить" (встроить один в другой), потому что они превышают лимиты по размеру байт-кода. В итоге каждый вызов этого метода – это честный переход по адресу в памяти, создание фрейма в стеке и куча лишних тактов процессора.

**Золотое решение:** Дробите логику на мелкие методы. Идеальный размер для инлайнинга – **до 35 байт байт-кода**. Красивый код по Clean Code внезапно оказывается самым быстрым для машины.

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

> **Голос JIT:** "У меня есть жёсткий лимит **MaxInlineSize**. Если метод крохотный, я просто копирую его тело в место вызова. Границы между методами исчезают, код становится монолитным и летит со скоростью света. Огромные методы я вынужден вызывать "по старинке" - с сохранением состояния стека и прыжками по адресами. Будьте проще, и я сделаю ваш код по-настоящему быстрым!"

> **Шёпот AOT:** "В Native Image я провожу глубокий анализ достижимости кода. Мелкие методы позволяют мне точнее определить, какие части программы никогда не будут вызваны, и полностью вырезать их при сборке. Чем чище структура ваших методов, тем стройнее и быстрее итоговый бинарник".

## Правило №6. Преаллокация коллекций
**В чём боль:** Создавая _new ArrayList<>()_, _new HashMap<>()_ и другие структуры данных без параметров, вы подписываете JVM на серию "переездов". Как только список наполняется, он создаёт массив побольше и копирует туда старые данные. Это лишние аллокации, фрагментация памяти и работа для GC.

**Золотое решение:** Задавайте Initial Capacity. В Java 19+ для этого появились ещё более удобные статические методы, которые сами учитывают коэффициент загрузки (Load Factor).

```java
import java.util.LinkedHashMap;

private Mono<ServerResponse> renderErrorResponse(ServerRequest request) {
    // Предварительное выделение 16 buckets
    Map<String, Object> errorProperties = LinkedHashMap.newLinkedHashMap(16);

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

> **Голос JIT:** "Каждый раз, когда массив внутри коллекции расширяется, я слышу плач Garbage Collector’a. Заранее заданный размер – это как забронированный столик в ресторане: никакой суеты и лишних движений. Я просто выделяю один кусок памяти и спокойно работаю с ним, не отвлекаясь на перекладывание байтов".

> **Шёпот AOT:** "В Native Image управление памятью ещё более строгое. Преаллокация позволяет мне лучше предсказать пиковое потребление RAM вашим приложением. Чем меньше у вас динамических расширений массивов, тем стабильнее и предсказуемее ведёт себя бинарник под нагрузкой".

## Правило №7. BigDecimal vs Long (Битва за примитивы)
**В чём боль:** _BigDecimal_ – это тяжёлый объект, внутри которого скрыт массив _int[]_. Любая арифметическая операция с ним – это создание нового объекта в памяти. В биллинге или высоконагруженных расчётах это генерирует тонны мусора в памяти, заставляя GC работать на износ.

**Золотое решение:** Храните денежные значения в минимальных единицах (копейки, центы) в типе _long_. Переходите на _BigDecimal_ только в самый последний момент – при выводе пользователю.

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

> **Голос JIT:** "_long_ – это просто 64 бита в моём регистре. Я храню его прямо в регистрах процессора. Сложение двух _long_ занимает доли наносекунды. С _BigDecimal_ я вынужден прыгать в кучу (Heap) за каждым числом и его масштабом. Выбирайте long, если не хотите, чтобы я буксовал на элементарной арифметике".

> **Шёпот AOT:** "В бинарном коде Native Image работа с _long_ превращается в одну инструкцию ассемблера. _BigDecimal_ же тянет за собой дерево зависимостей и сложную логику управления памятью. Чем больше примитивов, тем меньше мой исполняемый файл и тем быстрее он "прогревается"".

## Правило №8. Избегайте прокси в критических узлах
**В чём боль:** _@Transactional_ и _@Async_, _@Cacheable_ - это удобно, но за кулисами они  создают динамические обертки (Proxy) в рантайме. Каждый вызов проксированного метода - это лишний "прыжок" по объектам-перехватчикам, раздутый стек вызовов и невозможность глубокого инлайнинга. В высоконагруженных циклах это становится настоящим "стек-киллером".

**Золотое решение:** Держите бизнес-логику "чистой". Используйте аннотации только на верхнем уровне (Entry Points), а внутри сервисов вызывайте обычные private/package-private методы. Если вам нужно вызвать _@Transactional_ метод из того же класса - вы уже знаете, что прокси не сработает (self-invocation), и это отличный повод задуматься о декомпозиции.

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
        // обычный вызов метода
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
        // обычный вызов метода
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

> **Голос JIT:** "Прокси для меня – это лабиринт. Я вижу цепочку сгенерированных классов-оберток, через которые нужно продраться к реальному коду. Чем меньше магии между мной и вашим кодом, тем быстрее я построю прямой граф вызовов и применю **inlining**".

> **Шёпот AOT:** "Динамические прокси – мой враг номер один. Чтобы они работали в Native Image, мне приходится генерировать их заранее или тащить тяжёлый механизм рефлексии. Убирая лишние прокси, вы уменьшаете количество сгенерированных классов в бинарнике и ускоряете запуск приложения".

## Правило №9. Generics: Избегаем лишних кастов
**В чём боль:** Хотя в рантайме типы стираются (**Type Erasure**), использование _Object_ или **Raw Types** заставляет вас (и JVM) постоянно вставлять в байт-код инструкцию _checkcast_. Это не только небезопасно, но и заставляет процессор тратить лишние такты на проверку иерархии классов при каждом обращении к объекту.

**Золотое решение:** Используйте строго типизированные дженерики везде, где важна производительность. Это позволяет компилятору гарантировать типы на этапе сборки, а JIT-компилятору - строить машинный код без лишних "контрольно-пропускных пунктов".

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

> **Голос JIT:** "Каждый раз, когда я вижу _checkcast_, я вынужден притормозить и проверить: а точно ли этот объект в памяти совпадает с ожидаемым типом? С правильными дженериками я доверяю вашему коду на 100%. Для меня это скоростная трасса без светофоров и лишних проверок документов".

> **Шёпот AOT:** "В Native Image я провожу **Static Analysis** всей программы. Строгая типизация помогает мне точнее определить границы типов и исключить лишние проверки из бинарника. Чем меньше "неизвестных" _Object_, тем меньше проверок типов в рантайме и выше производительность".

## Правило №10. Статический анализ вместо динамического (MapStruct)
**В чём боль:** Библиотеки вроде _ModelMapper_ или злоупотребление _ObjectMapper.convertValue()_ - это "динамический налог" на производительность.  Они используют интроспекцию в рантайме, буквально "ощупывая" каждый объект в поисках подходящих полей через _getField()_ и _setAccessible(true)_. Для JIT это непрозрачный код, а для Native Image - конфиг-ад на тысячи строк.

**Золотое решение:** Переносите всю сложность на этап компиляции. Используйте кодогенерацию. **MapStruct** генерирует обычный Java-код target.set(source.get()) на этапе компиляции. Мы уже видели его мощь в Правиле №4, но здесь подчеркнём: **нулевой оверхед** в рантайме и полная прозрачность для оптимизаторов.

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
        // Чистый маппинг: ни одной операции рефлексии в рантайме!
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

> **Голос JIT:** "Для меня код от **MapStruct** – это подарок. Это прямой, понятный и предсказуемый поток инструкций. Я инлайню такие методы мгновенно, превращая маппинг в практически бесплатную операцию. Никаких поисков по именам полей в HashMap метаданных - только работа с регистрами процессора".

> **Шёпот AOT:** "Статический анализ – мой лучший друг. Поскольку **MapStruct** генерирует обычные вызовы методов, я вижу все связи между классами ещё при сборке бинарника. Мне не нужно гадать, какие поля вы захотите "потрогать" через рефлексию, поэтому я могу смело вырезать всё лишнее из итогового файла".

## Правило №11. Scoped Values вместо ThreadLocal
**В чём боль:** Мы десятилетиями хранили контекст пользователя или транзакции в _ThreadLocal_. Это работало, когда потоков было 200-500. Но в Java 21 вы включаете _spring.threads.virtual.enabled: true_ и запускаете 100_000 виртуальных потоков. Если каждый из них "присосётся" к тяжёлому объекту в _ThreadLocal_, ваш Heap лопнет быстрее, чем сработает первый GC. К тому же, _ThreadLocal_ - это изменяемая структура, что само по себе усложняет оптимизацию.

**Золотое решение:** Используйте **Scoped Values** (JEP 446 / 464). Они позволяют безопасно передать неизменяемые данные вниз по дереву вызовов. Как только выполнение выходит из блока - данные становятся недоступны, а память мгновенно готова к очистке. Никаких утечек из-за забытого _.remove()_.

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

> **Голос JIT:** "_ThreadLocal_ для меня - это тяжёлый рюкзак, который поток не снимает до самой смерти. Я не могу предсказать, когда он его снимет. _Scoped Value_ – это лёгкая эстафетная палочка: подержал, передал, и она исчезла. В мире миллиона виртуальных потоков это единственный способ не утонуть в бесконечных мапах внутри потоков".

> **Шёпот AOT:** "Поскольку область видимости Scoped Value жёстко ограничена блоком кода, я могу гораздо эффективнее анализировать время жизни объектов. Это помогает мне оптимизировать распределение памяти и уменьшить накладные расходы на переключение контекста в Native-бинарнике".

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
