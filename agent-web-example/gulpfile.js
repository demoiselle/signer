var gulp = require('gulp'),
    concat = require('gulp-concat'),
    rename = require('gulp-rename'),
    uglify = require('gulp-uglify'),
    uglifycss = require('gulp-uglifycss');

gulp.task('js', function() {
    gulp.src(['./src/js/**/*.js'])
        .pipe(rename('app.min.js'))
        .pipe(uglify())
        .pipe(gulp.dest('dist'));
});

gulp.task('js-lib', function() {
    return gulp.src([
        './node_modules/agent-web/dist/**/*.min.js',
        './node_modules/angular-loading-bar/build/**/*.min.js',
        './node_modules/angular-ui-notification/dist/**/*.min.js'
    ])
        .pipe(concat('lib.min.js'))
        .pipe(gulp.dest('dist'));
});

gulp.task('css', function() {
    gulp.src(['./src/css/**/*.css'])
        .pipe(rename('app.min.css'))
        .pipe(uglifycss({
            "maxLineLen": 80,
            "uglyComments": true
        }))
        .pipe(gulp.dest('dist'));
});

gulp.task('css-lib', function() {

    return gulp.src([
        './node_modules/agent-web/dist/**/*.min.css',
        './node_modules/angular-loading-bar/build/**/*.min.css',
        './node_modules/angular-ui-notification/dist/**/*.min.css'
    ])
        .pipe(concat('lib.min.css'))
        .pipe(uglifycss({
            "maxLineLen": 80,
            "uglyComments": true
        }))
        .pipe(gulp.dest('dist'));

});

gulp.task('html', function() {
    gulp.src(['./src/**/*.ico'])
        .pipe(gulp.dest('dist'));

    return gulp.src(['./src/**/*.html'])
        .pipe(gulp.dest('dist'));
});

gulp.task('watch', function() {
    gulp.watch('src/js/**/*.js', ['js']);
    gulp.watch('src/css/**/*.css', ['css']);
    gulp.watch('src/**/*.html', ['html']);
});

gulp.task('default', ['js', 'css', 'css-lib', 'html', 'js-lib', 'watch'], function() {

});